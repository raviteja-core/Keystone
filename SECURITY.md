# Security Policy

## Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 0.1.x   | :white_check_mark: | Active development (P0/P1 milestone) |
| < 0.1.0 | :x:                | Pre-release development snapshots |

## Reporting a Vulnerability

If you discover a security vulnerability within Keystone, please do **NOT** open a public issue.

Instead, please submit your report privately to the maintainer via email or GitHub Private Vulnerability Reporting:
- **Maintainer:** `raviteja-core`
- **Response window:** Initial acknowledgment within 48 hours, security triage and remediation timeline within 5 business days.

Please provide:
1. Description of the issue, affected endpoints or components (Auth Server, Authz Engine, Java Starter, Go SDK).
2. Proof of concept reproduction script or HTTP request trace.
3. Impact assessment under STRIDE threat classification.

## Known Architecture Limitations & Boundary Guarantees

As documented in `docs/SECURITY_CONSIDERATIONS.md`:
1. **Master Key Custody:** Local runtime uses AES-256-GCM encryption with `KEYSTONE_MASTER_KEY`. In production deployments, cloud KMS/HSM (e.g. AWS KMS, HashiCorp Vault) is strongly recommended.
2. **Rate Limiting:** P0–P4 uses in-memory token bucket rate limiting per process instance. Distributed rate limiting via Redis is scheduled for Phase 5.
3. **Zanzibar Writer Serialization:** Single-writer or serializable transactions are required for strict monotonic zookie revisions.
