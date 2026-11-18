# Authorized Security Audit & Vulnerability Analysis Platform

> **Defensive Cybersecurity Research & Posture Intelligence**  
> An enterprise-grade, web-based vulnerability assessment and attack surface management platform built strictly for authorized security researchers, compliance auditors, and defensive engineering teams.

---

## 🛡️ Core Purpose & Philosophy

Modern security engineering requires proactive, continuous inspection of attack surfaces without risking system instability or unintended exposure. This platform provides:

1. **Attack Surface & Architecture Mapping**: Catalog targets, hostnames, networks, and permitted testing methods.
2. **Non-Destructive Vulnerability Auditing**: Combine passive telemetry analysis and safe active probing.
3. **Evidence-Backed Findings Management**: Every vulnerability includes exact HTTP request/response proofs, non-destructive reproduction steps, and remediation guidance.
4. **Cryptographic Compliance Logging**: Every scan dispatch, authorization record, target registration, and abort is recorded in a tamper-evident SHA-256 hash chain.
5. **Strict Defensive Guardrails**: Scans are impossible without explicit, unexpired authorization records. Destructive payloads, password brute-forcing, malware, and persistence mechanisms are strictly prohibited.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      FRONTEND WEB CONSOLE (Next.js 15)                  │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │ Target & Auth│  │ Scan Console  │  │  Findings & │  │  Audit Log  │  │
│  │  Management  │  │ & Kill Switch │  │   Evidence  │  │  & Reports │  │
│  └──────┬───────┘  └───────┬───────┘  └──────┬──────┘  └──────┬──────┘  │
└─────────┼──────────────────┼─────────────────┼────────────────┼─────────┘
          │                  │ REST API / SSE  │                │
┌─────────▼──────────────────▼─────────────────▼────────────────▼─────────┐
│                     BACKEND ENGINE (FastAPI / Python 3.12)              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ SCOPE & AUTHORIZATION GATEWAY (Strict Pre-Flight Policy Enforcer) │  │
│  └─────────────────────────────────┬─────────────────────────────────┘  │
│                                    │                                    │
│  ┌───────────────────────┬─────────┴─────────────┬───────────────────┐  │
│  │   PASSIVE ENGINE      │  SAFE ACTIVE ENGINE   │ LOCAL LAB ENGINE  │  │
│  │  - Headers & Cookies  │  - HTTP Methods       │ - Simulated OWASP │  │
│  │  - TLS / SSL Config   │  - CORS Reflection    │   Top 10 Checks   │  │
│  │  - Info Disclosure    │  - Boundary Analysis  │ - Port 8888 Only  │  │
│  │  - Dependency Audit   │  - Auth & Redirects   │                   │  │
│  └───────────┬───────────┴───────────┬───────────┴─────────┬─────────┘  │
│              ▼                       ▼                     ▼            │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ NORMALIZATION & RISK ENGINE (CVSS v3.1 + Transparent Factor Math) │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │                                  │
│  ┌───────────────────────────────────┴───────────────────────────────┐  │
│  │ TAMPER-EVIDENT AUDIT LOGGER (Cryptographic Hash Chaining SHA-256) │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌───────────────────────┐                             ┌───────────────────────┐
│ PostgreSQL / SQLite   │                             │   SAFE LOCAL LAB      │
│ Relational Store      │                             │ (Isolated Toy Target) │
└───────────────────────┘                             └───────────────────────┘
```

---

## 🔒 Authorization Model & Safety Guardrails

### 1. Pre-Flight Authorization Gateway (`ScopeValidator`)
Before any network probe is dispatched:
- **Ownership Confirmation**: The user must attest ownership or explicit contractual permission.
- **Time-Window Enforced**: Scans are rejected if `now < valid_from` or `now > valid_until`.
- **Target Allowlisting**: Scans verify that target URLs resolve strictly within permitted IP ranges or registered hostnames.
- **Mode Permissions**: Active scans and Lab simulations require explicit opt-in flags in `permitted_methods`.
- **Unauthorized Scans Aborted**: Any violation terminates instantly and logs a `SCAN_BLOCKED_UNAUTHORIZED` compliance event.

### 2. Emergency Kill Switch (`cancel_scan`)
- Accessible from both the UI and REST API.
- Instantly cancels all running asynchronous scan workers via cancellation tokens.
- Drops open HTTP sockets immediately.
- Records user identity, timestamp, and reason in the cryptographic audit log.

### 3. Safe, Non-Destructive Scanning Tiers
- **Tier 1: Passive Analysis**  
  Inspects response headers (`CSP`, `HSTS`, `X-Content-Type-Options`), cookie flags (`HttpOnly`, `Secure`, `SameSite`), TLS certificates, `robots.txt`, and exposed server banners. Sends **zero intrusive payloads**.
- **Tier 2: Safe Active Testing**  
  Probes safe HTTP verbs (`OPTIONS`, `HEAD`), benign CORS origin reflection testing (`Origin: https://audit.test.local`), and parameter length boundaries without executing payloads or injecting shell syntax.
- **Tier 3: Safe Local Lab Simulation**  
  Runs strictly against localhost/toy application ports (`http://localhost:8888`), testing educational OWASP Top 10 patterns (IDOR, open redirect, weak session storage) without affecting external networks.

---

## ⛓️ Tamper-Evident Cryptographic Audit Trail

Every state change is recorded in an immutable ledger using SHA-256 hash chaining:

$$H_0 = 0^{64} \quad \text{(Genesis Zero Hash)}$$
$$H_n = \text{SHA-256}(H_{n-1} \parallel \text{Seq}_n \parallel \text{Timestamp}_n \parallel \text{User}_n \parallel \text{Action}_n \parallel \text{Details}_n)$$

The web interface includes an interactive **"Verify Hash Chain"** tool that recomputes the entire cryptographic sequence to mathematically prove that no audit record has been inserted, altered, or deleted.

---

## 🚀 Quickstart Guide

### Option A: Native Single-Command Launch (Recommended for macOS)

No Docker installation required. The native runner automatically manages virtual environments and launches all three services:

```bash
# 1. Navigate to the repository
cd /Users/shauryashah/AG/security-audit-platform

# 2. Start all services
./run_local.sh
```

This starts:
- **Frontend Console**: [http://localhost:3000](http://localhost:3000)
- **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Safe Local Lab Target**: [http://localhost:8888](http://localhost:8888)

**Default Credentials:**
- **Username**: `admin`
- **Password**: `Admin@12345`

*Press `Ctrl+C` in the terminal at any time to trigger a clean shutdown of all platform services.*

---

### Option B: Docker Compose Deployment

```bash
docker-compose up --build
```

Services initialized:
- `security_audit_postgres`: Port 5432 (PostgreSQL 16)
- `security_audit_backend`: Port 8000 (FastAPI)
- `security_audit_frontend`: Port 3000 (Next.js 15)
- `security_audit_local_lab`: Port 8888 (FastAPI Toy Target)

---

## 🧪 Testing & Verification

### Automated Backend Test Suite
Run the 9 rigorous unit and integration tests covering scope enforcement, audit hash chain verification, passive headers, and safe active CORS analysis:

```bash
cd backend
.venv/bin/pytest -v
```

Expected output:
```
tests/test_scope_validator.py::test_unauthorized_target_rejected PASSED
tests/test_scope_validator.py::test_expired_authorization_aborted PASSED
tests/test_scope_validator.py::test_out_of_scope_target_rejected PASSED
tests/test_audit_hash_chain.py::test_audit_log_hash_chain PASSED
tests/test_audit_hash_chain.py::test_audit_log_tamper_detection PASSED
tests/test_scanners.py::test_passive_headers_scanner PASSED
tests/test_scanners.py::test_safe_active_cors PASSED
tests/test_api.py::test_health_endpoint PASSED
tests/test_api.py::test_login_and_token PASSED
============================== 9 passed in 0.82s ===============================
```

### Frontend Build Verification
Verify that all Next.js App Router routes compile cleanly with zero TypeScript or linting errors:

```bash
cd frontend
npm run build
```

---

## 📊 Risk Engine & Scoring Formula

The platform computes risk scores transparently using standard CVSS v3.1 weighting:

$$\text{Risk Score} = \text{BaseSeverity} \times (\text{Exploitability} \times 0.35 + \text{Exposure} \times 0.35 + \text{Impact} \times 0.30)$$

- **Critical**: 9.0 – 10.0
- **High**: 7.0 – 8.9
- **Medium**: 4.0 – 6.9
- **Low**: 0.1 – 3.9
- **Info**: 0.0

### Posture Index
$$\text{Posture Index} = 100 - \sum (\text{Penalty}_{\text{severity}})$$
Provides executive leadership with an intuitive 0–100 benchmark of defense readiness.

---

## 📄 Executive & Technical Reports

The platform generates audit-grade compliance reports with 1 click:
- **Interactive HTML Document**: Complete with executive summary, severity matrix, OWASP Top 10 distribution, cryptographic proof hashes, and remediation priority roadmap.
- **Executive Markdown Summary**: Formatted for inclusion in Jira, GitHub Security Advisories, or compliance submissions.
- **Print / PDF Export**: Clean, printable formatting optimized for print stylesheets.

---

## ⚖️ Legal & Ethical Notice

This software is developed strictly for **authorized, defensive security research**, compliance verification, and infrastructure hardening. Running security audits against systems without written permission is illegal in many jurisdictions. Always obtain explicit consent and retain signed authorization agreements.
