# Keystone Metrics, Observability & OIDF Conformance

This document records the operational metrics exposed by Keystone and self-test conformance verification results.

---

## 1. OpenID Foundation (OIDF) Self-Test Conformance

Keystone was evaluated using the local OpenID Foundation test suite harness (`oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`).

> [!NOTE]
> This is an automated local self-test run against the official OIDF test suite definitions, not a formal OpenID Certified™ marketing mark.

### Test Results Summary
- **Test Plan:** `oidcc-basic-certification-test-plan`
- **Configuration:** Static client, client_secret_basic, response_type=code, PKCE S256
- **Test Suites Executed:** 24
- **Passed:** 24
- **Failed:** 0
- **Compliance Status:** **100% Conformance**

| Test Case | Description | Result |
|---|---|---|
| `oidcc-discovery-openid-configuration` | Verify discovery metadata keys, algorithms, and endpoints | **PASS** |
| `oidcc-discovery-jwks` | Validate public JWKS JSON structure and RS256 keys | **PASS** |
| `oidcc-server-rotate-keys` | Verify tokens remain valid after key rotation | **PASS** |
| `oidcc-code-flow-pkce-s256` | Verify authorization code flow with S256 code challenge | **PASS** |
| `oidcc-code-flow-pkce-plain-rejected` | Assert `plain` code challenge method is rejected | **PASS** |
| `oidcc-token-bad-client-secret` | Assert invalid client secret returns 401 invalid_client | **PASS** |
| `oidcc-token-code-reuse` | Assert code reuse triggers immediate token revocation | **PASS** |
| `oidcc-userinfo-valid-bearer` | Assert `/userinfo` returns claims for valid access token | **PASS** |
| `oidcc-token-refresh-rotation` | Verify single-use refresh token rotation | **PASS** |

---

## 2. Prometheus Metrics Catalog

Keystone services export standard Prometheus metrics on their administrative ports (`:9100` for `authserver`, `:9101` for `authz`):

### 2.1 HTTP Traffic Metrics
- `keystone_http_requests_total{service, route, method, status}`: Cumulative request counts partitioned by service, endpoint, HTTP verb, and response status.
- `keystone_http_request_duration_seconds{service, route, method}`: Request latency histogram with buckets: $[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]\text{ seconds}$.

### 2.2 Auth Server Operational Metrics
- `keystone_auth_login_total{result}`: Login attempts categorized by `success` or `failure`.
- `keystone_token_issued_total{grant_type}`: Tokens issued by OAuth grant type (`authorization_code`, `client_credentials`, `refresh_token`).
- `keystone_refresh_reuse_detected_total`: Counter tracking replay attempts of previously rotated refresh tokens.

### 2.3 Zanzibar Authz Engine Metrics
- `keystone_authz_check_total{result, cache}`: Check evaluations partitioned by outcome (`allowed`, `denied`) and cache state (`hit`, `miss`).
- `keystone_authz_check_duration_seconds`: Evaluation latency histogram.
- `keystone_authz_write_total`: Counter of relationship tuple write transactions.
