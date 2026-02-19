# Security Policy

## ⚠️ This Repository is Intentionally Vulnerable

This is a **demo repository** designed to showcase GitHub Advanced Security (GHAS) capabilities. All vulnerabilities are **intentional** — do not use this code in production.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## GHAS Features Demonstrated

### 🔍 CodeQL Code Scanning
- **Standard queries**: `security-and-quality` + `security-extended` suites
- **Custom queries**: 4 custom QL queries in `.github/codeql/custom-queries/`
  - `HardcodedCryptoKey.ql` — Detects hardcoded secrets in variable declarations (CWE-798)
  - `UnsafeDeserialization.ql` — Traces user input to `node-serialize` sinks (CWE-502)
  - `ECBModeEncryption.ql` — Finds AES-ECB usage (CWE-327)
  - `SensitiveTempFile.ql` — Catches sensitive data written to `/tmp` (CWE-312)
- **Actions scanning**: Detects expression injection in GitHub Actions workflows
- **Multi-language matrix**: JavaScript/TypeScript + Actions

### 🔑 Secret Scanning
- **Provider patterns**: AWS keys, GitHub tokens, Stripe keys, SendGrid, Slack webhooks
- **Push protection**: Blocks commits containing detected secrets
- **Non-provider patterns**: Enabled for broader detection
- **Committed `.env` file**: Demonstrates why `.env` should be in `.gitignore`

### 📦 Dependabot
- **Multi-ecosystem groups**: npm + pip + Docker in consolidated PRs
- **Glob directories** (`/**`): Auto-discovers package files in all subdirectories
- **Grouped updates**: `all-node-deps`, `all-python-deps`, `all-docker` groups
- **Intentionally outdated deps**: lodash 4.17.4, marked 0.3.9, node-serialize 0.0.4, etc.

### 🔄 Dependency Review
- Runs on every PR via `.github/workflows/dependency-review.yml`
- Blocks PRs that introduce packages with known CVEs

### 🛡️ Third-Party Scanners (SARIF Upload)
- **Anchore Grype**: Container and dependency vulnerability scanner
- **Trivy**: Comprehensive vulnerability scanner
- **njsscan**: Node.js-specific security scanner

## Vulnerability Categories

| Category | CWE | Files | Count |
|----------|-----|-------|-------|
| SQL Injection | CWE-89 | model/auth.js, products.js, user_db.js, helpers.js | 12+ |
| Command Injection | CWE-78 | routes/admin.js, api.js, helpers.js, email_service.js | 7+ |
| Path Traversal | CWE-22 | routes/admin.js, files.js, api.js, helpers.js | 8+ |
| XSS (Reflected) | CWE-79 | routes/admin.js, users.js, api.js, helpers.js | 6+ |
| Code Injection | CWE-94 | routes/admin.js, api.js, helpers.js (eval) | 4+ |
| SSRF | CWE-918 | routes/admin.js, api.js, email_service.js | 3+ |
| Insecure Deserialization | CWE-502 | routes/admin.js, api.js, helpers.js | 3+ |
| Prototype Pollution | CWE-1321 | routes/admin.js, api.js, users.js, middleware | 4+ |
| Weak Crypto | CWE-327/328 | helpers.js, config.js, routes/admin.js | 5+ |
| Hardcoded Secrets | CWE-798 | config.js, .env, helpers.js | 10+ |
| Cleartext Logging | CWE-312 | middleware/security.js, helpers.js, routes | 5+ |
| Broken Access Control | CWE-285 | middleware/security.js, routes/api.js | 3+ |
| Actions Injection | CWE-78 | .github/workflows/auto-label.yml | 3 |

## Cross-File Taint Flows

This repo specifically demonstrates CodeQL's **cross-file taint analysis**:

- **2-file chains**: `req → route → helpers.js → sink` (most vulnerabilities)
- **3-file chains**: `req → route → user_db.js → helpers.js → SQL`
- **4-file chains**: `req → api.js → email_service.js → helpers.js → exec()`

## Demo Script

1. **Security Overview** → Show the Security tab: code scanning alerts, secret alerts, Dependabot alerts
2. **CodeQL alerts** → Click any alert to show the vulnerability description, affected code, and data flow path
3. **Copilot Autofix** → Show AI-suggested fixes on CodeQL alerts
4. **Custom queries** → Explain how `.github/codeql/custom-queries/` extends detection
5. **Secret scanning** → Show detected secrets in config.js and .env
6. **Push protection** → Try pushing a new secret — it gets blocked
7. **Dependabot** → Show the ecosystem-grouped PRs, auto-discovered across directories
8. **Dependency review** → Open a PR introducing a vulnerable package — it blocks the merge
9. **Actions scanning** → Show the workflow injection alerts from auto-label.yml
10. **SARIF integration** → Third-party tools (Grype, Trivy) feed into the same Security tab

## Reporting a Vulnerability

This is a demo repo — all vulnerabilities are intentional. If you discover a security vulnerability in the demo infrastructure itself, please report it via [GitHub Security Advisories](../../security/advisories/new).
