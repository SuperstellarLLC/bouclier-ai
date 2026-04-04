# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue.
2. Email **security@ilvarion.dev** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive an acknowledgment within **48 hours**.
4. We aim to provide a fix within **7 days** of confirmation.

## Security Measures

This project implements:

- Content Security Policy (CSP) with nonces
- Strict security headers (HSTS, X-Frame-Options, etc.)
- Rate limiting on all routes
- Environment variable validation with Zod
- Dependency auditing in CI
- Docker container runs as non-root user
