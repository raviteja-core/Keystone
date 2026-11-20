# Keystone Threat Model & Security Architecture

This document provides a comprehensive STRIDE threat modeling analysis of Keystone IAM and Zanzibar Authorization Engine, mapping security controls against known attack vectors per RFC 6749, RFC 7636, RFC 9068, and RFC 9700 (OAuth 2.0 Security Best Current Practice).

---

## 1. STRIDE Threat Matrix

| STRIDE Category | Threat Description | Attack Vector / Impact | Keystone Mitigation & Architectural Defense |
|---|---|---|---|
| **Spoofing** | Client Impersonation | Public client masquerades as a confidential client to steal authorization grants. | Strict client registration with enforced `client_type` (`confidential` vs `public`). PKCE (`code_challenge_method=S256`) is **strictly enforced** for all authorization code flows. `client_secret` hashes verified using constant-time comparison. |
| **Spoofing** | User Identity Spoofing | Adversary crafts forged JWT access tokens or tampers with `sub` claim. | Tokens signed via RSA RS256 with 2048/3072-bit keys. Verifiers strictly validate `iss`, `aud`, `exp`, `nbf`, and enforce `typ: at+jwt` (RFC 9068). Algorithmic confusion (`none`, HMAC with public key) is actively rejected by hardcoded RS256 algorithm allowlists. |
| **Tampering** | Audit Log Manipulation | An adversary or compromised administrator alters or deletes security logs to erase evidence. | `audit_events` table is protected by PostgreSQL triggers rejecting `UPDATE`, `DELETE`, and `TRUNCATE`. Records are linked using a cryptographic SHA-256 hash chain (`hash = SHA256(prev_hash \|\| canonical_payload)`). Chain integrity is verifiable offline via `keystonectl audit verify`. |
| **Tampering** | Relationship Tuple Tampering | Malicious actor inserts arbitrary tuples into ReBAC store granting unauthorized access. | Zanzibar schema validation ensures relation names, resource types, and subject formats conform to compiled schema definitions before write. Write operations are atomic and generate monotonic revisions. |
| **Repudiation** | Action Non-Repudiation | User or service denies performing a sensitive permission check or token issuance. | Every authorization code exchange, token grant, failed login attempt, and relationship change writes an immutable audit record with client IP, user agent, actor ID, request ID, and timestamp. |
| **Information Disclosure** | Token Leakage via Referrer / Browser History | Authorization codes or access tokens intercepted via browser history or access logs. | Implicit grant (`response_type=token`) is **completely disallowed** per RFC 9700 §2.1.2. Only authorization code flow with PKCE is supported. Tokens are transported via HTTP POST bodies with `Cache-Control: no-store` and `Pragma: no-cache`. |
| **Information Disclosure** | Private Key Exposure | Accidental exposure of private key material through public JWKS endpoints. | Key manager extracts only `rawJWK.Public()` before caching or serialization. Private keys in the database are encrypted at rest using AES-256-GCM with master key wrapping and authenticated additional data (`kid`). |
| **Denial of Service** | Argon2id Hash Flooding | Attacker sends concurrent login requests to exhaust server CPU and memory. | Password hashing uses a bounded concurrency semaphore (`MaxConcurrent`). Sliding-window rate limiters reject excessive attempts before invoking Argon2id. |
| **Denial of Service** | Zanzibar Graph Explosion (ReDoS / Cycle) | Cyclic or deeply nested relationship rules cause infinite loops or stack overflow. | Recursive Zanzibar evaluation enforces an explicit maximum recursion depth ($32$) and tracks visited resource-relation pairs in a cycle-detection set. |
| **Elevation of Privilege** | Authorization Code / Refresh Token Reuse | Intercepted authorization code or refresh token used to obtain unauthorized access. | Single-use authorization codes are deleted atomically upon exchange; reuse detection revokes all downstream tokens. Refresh tokens use single-use rotation: exchanging a refresh token invalidates it and issues a new pair; replaying an old refresh token immediately invalidates the entire token family. |

---

## 2. Key Cryptographic Protocols & Invariants

### 2.1 RFC 9068 Profiled Access Tokens
- **Header Enforcement:** All JWT access tokens issued by Keystone require:
  ```json
  {
    "alg": "RS256",
    "typ": "at+jwt",
    "kid": "<thumbprint-sha256>"
  }
  ```
- **Rejection of Ambiguous Tokens:** Verifiers must reject any token lacking `typ: at+jwt` to prevent cross-JWT confusion attacks (e.g. submitting an OpenID Connect `id_token` or logout token to a resource server expecting an access token).

### 2.2 Replay Protection (RFC 6238 TOTP §5.2)
- TOTP verifiers enforce a strict monotonic timestep invariant: `step > lastUsedStep`.
- Even within the valid 30-second window, an OTP code cannot be replayed twice.

### 2.3 Monotonic Zookie Invariant & New Enemy Problem
- Read operations take a `Consistency` parameter:
  - `minimize_latency`: Reads from local cache or replica.
  - `at_least_as_fresh`: Ensures read replica has caught up to the transaction revision in the caller's Zookie.
  - `fully_consistent`: Directly evaluates against primary database with serializable snapshot isolation.
- This guarantees read-your-writes consistency across distributed microservices.
