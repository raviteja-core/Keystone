# Keystone Security Considerations & Implementation Guidelines

This guide details operational security practices, cryptographic parameter selections, and protocol specifications implemented in Keystone.

---

## 1. OAuth 2.0 Security BCP Compliance (RFC 9700)

Keystone adheres strictly to RFC 9700 (OAuth 2.0 Security Best Current Practice) and eliminates legacy insecure authorization flows:

1. **No Implicit Grant Flow:**
   - The implicit grant (`response_type=token`) and hybrid flows transmitting access tokens in the URL fragment are disabled.
   - All browser-based Single Page Applications (SPAs) and native apps must use Authorization Code Flow with PKCE.

2. **Proof Key for Code Exchange (PKCE - RFC 7636):**
   - PKCE is mandatory for all clients, whether confidential or public.
   - Only `code_challenge_method=S256` is accepted; `plain` is forbidden.
   - Code verifiers are validated using constant-time comparisons (`crypto/subtle.ConstantTimeCompare`).

3. **Exact Redirect URI Matching:**
   - Wildcards, path traversals, or open query strings in registered `redirect_uri` entries are rejected.
   - Exact string equality is enforced during the authorization request.

4. **Token Revocation (RFC 7009):**
   - Revocation endpoint `/revoke` allows confidential clients to invalidate refresh tokens and token families immediately.
   - Per RFC 7009 §2.2, revoking an invalid or already revoked token returns HTTP 200 OK to prevent token enumeration timing attacks.

5. **Token Introspection (RFC 7662):**
   - Protected endpoint `/introspect` allows internal resource servers to verify token validity, scope, audience, and active status in real-time.

---

## 2. Cryptographic Key Management & Rotation

1. **Envelope Encryption:**
   - All RSA private signing keys stored in PostgreSQL are encrypted at rest using AES-256-GCM.
   - Encryption uses a 32-byte master key (`KEYSTONE_MASTER_KEY`).
   - A unique 12-byte cryptographic nonce is generated per key encryption operation.
   - The key ID (`kid`) is passed as Authenticated Additional Data (AAD) to prevent key substitution.

2. **Zero Private Key Exposure:**
   - Public JWKS endpoints (`/.well-known/jwks.json`) extract only `jose.JSONWebKey.Public()` structures. Private components ($d, p, q, dp, dq, qinv$) are stripped before serialization.

3. **Key Rotation Lifecycle:**
   - When a new key is activated via `keystonectl keys rotate`:
     1. A new RSA key pair is generated (2048 or 3072 bits).
     2. The active key's status changes to `retired`.
     3. The new key is marked `active`.
     4. Public JWKS includes both `active` and `retired` keys so previously issued, unexpired tokens continue to validate.
     5. Only `revoked` keys are omitted from the JWKS.

---

## 3. Password Storage (Argon2id)

Passwords are hashed using Argon2id per OWASP Password Storage Cheat Sheet recommendations:
- **Memory Cost ($m$):** 64 MiB (65536 KiB)
- **Time Cost ($t$):** 3 iterations
- **Parallelism ($p$):** 2 threads
- **Salt Length:** 16 cryptographically random bytes (`crypto/rand`)
- **Key Length:** 32 bytes

To prevent denial of service through concurrent resource exhaustion, Keystone wraps password verification in a semaphore limiting concurrent Argon2id hashing operations (`Argon2MaxConcurrent`).

---

## 4. Relationship-Based Access Control (ReBAC) Consistency

Keystone’s Zanzibar authorization engine prevents the **"New Enemy"** problem through monotonic Zookies:

1. **Zookie Composition:**
   - A Zookie is an opaque token encoding `[tenant_id]:[revision_id]:[checksum]`.
   - Every tuple write increments the tenant revision counter monotonically.

2. **Evaluation Modes:**
   - `at_least_as_fresh(zookie)`: Ensures evaluation queries only read from snapshot revisions $\ge$ the revision encoded in the client's Zookie.
   - `fully_consistent`: Forces direct query against the primary PostgreSQL database with read consistency.
   - `minimize_latency`: Allows bounded read from local caches (e.g. Caffeine in Spring Boot, Redis in distributed nodes). Cached entries are automatically bypassed when `fully_consistent` is requested.
