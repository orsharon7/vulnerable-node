# 🔓 Vulnerable Node — GHAS Demo Repository

An intentionally vulnerable Node.js application built to showcase **GitHub Advanced Security (GHAS)** capabilities.

> ⚠️ **Do not deploy this to production.** Every vulnerability is intentional.

---

## What This Repo Demonstrates

### 🔍 Code Scanning (CodeQL)

| What | How |
|------|-----|
| **80+ security alerts** across SQL injection, command injection, XSS, SSRF, path traversal, and more | `security-and-quality` + `security-extended` query suites |
| **Cross-file taint tracking** — traces data flow across 2–4 files | `req → route → service → helper → sink` chains |
| **Custom CodeQL queries** — extend detection beyond built-in rules | 4 custom `.ql` files in `.github/codeql/custom-queries/` |
| **GitHub Actions scanning** — detects expression injection in workflows | `auto-label.yml` has 3 injectable expressions |
| **Copilot Autofix** — AI-suggested fixes on every alert | Click "Generate fix" on any code scanning alert |

### 🔑 Secret Scanning

| What | How |
|------|-----|
| **Hardcoded secrets detected** — AWS, GitHub, Stripe, SendGrid, Slack | `config.js` + committed `.env` file |
| **Push protection** — blocks pushes containing secrets | Try committing a real-format API key — it gets rejected |
| **Multiple provider patterns** — each secret type identified by provider | See Security → Secret scanning alerts |

### 📦 Dependabot

| What | How |
|------|-----|
| **176 vulnerability alerts** (26 critical) across 4 ecosystems | npm, pip, Docker — intentionally outdated deps |
| **Multi-ecosystem groups** — one PR updates all npm deps across all directories | `dependabot.yml` with `multi-ecosystem-groups` + glob `/**` |
| **Auto-discovery** — finds `package.json`, `requirements.txt`, `Dockerfile` everywhere | Root, `services/api/`, `services/frontend/`, `tools/scripts/` |

### 🔄 Dependency Review

| What | How |
|------|-----|
| **PR gating** — blocks merges that introduce known-vulnerable packages | `.github/workflows/dependency-review.yml` |

### 🛡️ Third-Party SARIF Integration

| Tool | What It Finds |
|------|---------------|
| **Anchore Grype** | Container + dependency CVEs |
| **Trivy** | OS packages, language deps, IaC misconfigs |
| **njsscan** | Node.js-specific security patterns |

All results feed into the **same Security tab** — unified view.

---

## Vulnerability Coverage

| Category | CWE | Example |
|----------|-----|---------|
| SQL Injection | 89 | String-concatenated queries in every model file |
| Command Injection | 78 | `exec('ping ' + userInput)` in admin + API routes |
| Path Traversal | 22 | Unsanitized file paths in download/upload/export |
| XSS | 79 | Raw HTML rendering of user content |
| Code Injection | 94 | `eval(req.body.expression)` |
| SSRF | 918 | Server fetches any user-provided URL |
| Insecure Deserialization | 502 | `node-serialize.unserialize(userInput)` |
| Prototype Pollution | 1321 | Recursive merge without `__proto__` check |
| Weak Cryptography | 327 | AES-ECB mode, MD5 password hashing |
| Hardcoded Secrets | 798 | AWS keys, JWT secret, Stripe key in source |
| Cleartext Logging | 312 | Passwords + tokens logged to files |
| Broken Access Control | 285 | Trusts `X-User-Role` header |
| Actions Injection | 78 | `${{ github.event.pull_request.title }}` in shell |

---

## Advanced Configuration Highlights

- **Custom CodeQL queries** — `.github/codeql/custom-queries/*.ql`
- **Custom CodeQL config** — `.github/codeql/codeql-config.yml` (threat models, path scoping)
- **Multi-language CodeQL matrix** — JavaScript/TypeScript + Actions
- **Dependabot ecosystem groups** — consolidates PRs across directories
- **CODEOWNERS** — requires review for security config changes
- **SECURITY.md** — full demo walkthrough with 10-step script

---

## Quick Links

| Resource | Link |
|----------|------|
| Security Overview | [Security tab](../../security) |
| Code Scanning Alerts | [Code scanning](../../security/code-scanning) |
| Secret Scanning Alerts | [Secret scanning](../../security/secret-scanning) |
| Dependabot Alerts | [Dependabot](../../security/dependabot) |

---

*Based on [cr0hn/vulnerable-node](https://github.com/cr0hn/vulnerable-node). Extended by Or Sharon for GHAS demonstrations.*
