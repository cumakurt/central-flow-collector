# Security

v4 security protects the collector itself; it is not a security-detection product.

- Roles: Administrator, Analyst, Read Only.
- Password hashes use PBKDF2; local MFA/TOTP and WebAuthn/passkeys are available.
- OIDC validates issuer/audience/time/state/nonce/JWKS; LDAP should use LDAPS.
- API tokens are stored as hashes and can carry scopes, expiry and source-CIDR restrictions.
- Browser mutations require CSRF tokens; CSP and other browser headers are set by the server.
- Diagnostics/pprof is disabled by default.
- Audit events are integrity chained.
- Secrets can be sourced from environment variables or protected files.
- Exporter allow/deny policies and packet-rate limits protect the UDP ingestion surface.

Do not expose the HTTP portal directly to untrusted networks without TLS/reverse-proxy controls appropriate to your environment.
