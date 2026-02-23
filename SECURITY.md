# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 6.x (latest) | ✅ Active security fixes |
| 5.x | ⚠️ Critical fixes only |
| < 5.0 | ❌ End of life |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

### Preferred: Private Disclosure

Email: **security@ailydian.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 24 hours |
| Initial assessment | Within 72 hours |
| Status update | Within 7 days |
| Resolution target | Within 30 days (critical: 7 days) |

### Scope

**In scope:**
- Authentication and authorization bypass
- Remote code execution
- SQL injection / command injection
- Cross-site scripting (XSS)
- Sensitive data exposure
- Cryptographic weaknesses
- SSRF / path traversal

**Out of scope:**
- Social engineering
- Physical security
- Denial of service (without meaningful impact proof)
- Issues in third-party dependencies (report upstream)

## CVSS Risk Classification

| Severity | CVSS Score | Response SLA |
|----------|-----------|--------------|
| Critical | 9.0–10.0 | 7 days |
| High | 7.0–8.9 | 14 days |
| Medium | 4.0–6.9 | 30 days |
| Low | 0.1–3.9 | 90 days |

## Security Architecture

TSUNAMI implements defense-in-depth:

- **Authentication**: JWT with Argon2id password hashing, optional 2FA (TOTP)
- **Authorization**: Role-based access control (RBAC) with least-privilege defaults
- **Transport**: TLS 1.3 enforced in production (Flask-Talisman)
- **Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Rate limiting**: Per-endpoint limits via Flask-Limiter + Redis
- **CSRF**: Token-based protection on all state-changing requests
- **Secrets**: All secrets via environment variables — never hardcoded
- **Dependencies**: Automated CVE scanning via `safety` and `pip-audit`
- **Audit trail**: All privileged actions logged with timestamps and IP addresses

## Responsible Disclosure

We follow [coordinated vulnerability disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html). Researchers who responsibly disclose valid vulnerabilities will be credited in our release notes (with their permission).

## Security Compliance

- OWASP Top 10 (2021) — tested in CI via OWASP ZAP
- Flask-Talisman security headers
- Pre-commit: `detect-secrets`, `bandit` static analysis
- CI/CD: Trivy container scanning, TruffleHog secret detection

---

*For general questions, open a [GitHub Discussion](https://github.com/lydianai/tsunami/discussions).*
