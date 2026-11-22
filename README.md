# Mini-VulnFinBot — Secure CI/CD Pipeline with AI-Specific Security Controls

Mini-VulnFinBot is a small AI-powered personal-finance assistant (Flask REST API) used to
demonstrate a production-style **DevSecOps pipeline**: every push runs unit tests, SAST,
dependency scanning, container scanning, DAST and AI-specific security tests, and stores
all reports as GitHub Actions artifacts.

> The full technical report (findings, remediation, before/after comparison, screenshots)
> is in [`docs/technical-report.md`](docs/technical-report.md).

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.12, Flask, gunicorn | Application and production WSGI server |
| pytest | Unit tests and AI security tests |
| GitHub Actions | CI/CD automation, artifact storage |
| Bandit, Semgrep (custom rules) | SAST |
| pip-audit | Python dependency vulnerability scanning |
| Docker (python:3.12-alpine), Trivy | Containerization and image scanning |
| OWASP ZAP (baseline) | DAST |
| GitHub Models (`openai/gpt-4o-mini`) | Real LLM for prompt-injection tests in CI (optional) |

## Architecture

```
            ┌──────────────── Flask app (app/) ────────────────┐
 HTTP ──►   │ routes.py  : JSON validation, size/type checks,   │
            │              generic JSON errors, no PII in logs  │
            │ assistant.py:                                     │
            │   1. input guardrails (injection / disclosure)    │
            │   2. model  (MockModel | GitHub Models | Claude)  │
            │   3. tool authorization (allow-list per role)     │
            │   4. output validation (canary, secret redaction, │
            │      HTML escaping, length limit)                 │
            │ __init__.py: security headers, error handlers     │
            └───────────────────────────────────────────────────┘
```

The model is treated as **untrusted**: its text and its requested tool calls are checked by
application code before reaching the user.

### API

| Method | Path | Description |
|---|---|---|
| GET | `/health` | `{"status": "healthy"}` |
| POST | `/api/chat` | body `{"message": "..."}` (1–1000 chars) → `{"response": "..."}` |

Error responses are always JSON (`{"error": ..., "status": ...}`) with 400 / 413 / 415 / 404 / 405 / 500.

## Project structure

```
app/                       Flask application (factory, routes, AI assistant + guardrails)
tests/test_app.py          API tests (validation, errors, headers, logging)
tests/test_ai_security.py  AI security scenarios (prompt injection, disclosure, tools, output)
security/semgrep/rules.yml Custom Semgrep rules (11 rules incl. LLM-specific ones)
security/ai_security_report.py  Generates reports/ai-security-report.md
security/summarize_reports.py   Builds the summary table from all scanner reports
.github/workflows/security-pipeline.yml  CI/CD pipeline
docs/                      Technical report, screenshots, before/after evidence
reports/                   Generated reports (git-ignored, published as artifacts)
```

## Installation

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt   # runtime + pytest, bandit, semgrep, pip-audit
```

## Running the application

```bash
python run.py                          # http://127.0.0.1:5000
# or with Docker
docker build -t vulnfinbot:latest .
docker run --rm -p 5000:5000 vulnfinbot:latest
curl http://localhost:5000/health
curl -X POST http://localhost:5000/api/chat -H "Content-Type: application/json" \
     -d '{"message": "How can I manage my monthly budget?"}'
```

> On macOS port 5000 is used by AirPlay Receiver — use `-p 5050:5000` instead.

To use a real LLM instead of the mock: `LLM_PROVIDER=github GITHUB_TOKEN=<token with models:read>`
or `LLM_API_KEY=<Anthropic key>` (test environment only, never production credentials).

## Running tests

```bash
pytest -v                               # all tests (real-LLM tests are skipped without an LLM)
pytest -v tests/test_ai_security.py     # AI security tests only
python -m security.ai_security_report   # writes reports/ai-security-report.md
```

## Running the security scanners locally

```bash
mkdir -p reports
bandit -r app/ run.py -f json -o reports/bandit-report.json
semgrep scan --config security/semgrep/rules.yml --json --output reports/semgrep-report.json app/ run.py
pip-audit -r requirements.txt -f json -o reports/dependency-report.json
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/reports:/out" \
  aquasec/trivy:0.62.1 image --format json --output /out/trivy-report.json vulnfinbot:latest
docker run --rm --network host -v "$PWD/reports:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 -J zap-report.json -r zap-report.html -I
python security/summarize_reports.py reports/
```

## CI/CD pipeline

Triggered on push to `main` and `security-test/**`, on pull requests to `main`, and manually.

```
                 ┌─► SAST (Bandit + Semgrep) ──────────────┐
 Unit tests ─────┼─► Dependency scan (pip-audit) ──────────┤
                 ├─► Docker build + smoke test + Trivy ─► DAST (ZAP) ─┤─► Collect security reports
                 └─► AI security tests (mock + real LLM) ──┘
```

| Job | What it does | Gate (fails the pipeline) |
|---|---|---|
| Unit tests | `pytest tests/test_app.py`, JUnit XML | any failing test |
| SAST | Bandit + Semgrep custom rules → JSON/TXT | Bandit HIGH, Semgrep ERROR |
| Dependency scan | pip-audit on `requirements.txt` | any known vulnerability |
| Docker + Trivy | build, smoke test `/health` + `/api/chat`, Trivy JSON/table | fixable CRITICAL CVEs |
| DAST | run container, ZAP baseline → JSON/HTML/MD | report only (`-I`) |
| AI security | 14 app-level scenarios + 3 real-LLM scenarios (GitHub Models) | app-level failures |
| Collect reports | merges all reports, builds `security-summary.md`, job summary | — |

Every scanner writes its report in a `continue-on-error` step, uploads it with `if: always()`,
and only then runs its gate — so a failing scanner never prevents report upload.

## Security tools

* **Bandit** — Python-specific SAST (hardcoded secrets, `eval`, `shell=True`, weak hashes, pickle…).
* **Semgrep** — custom rules in `security/semgrep/rules.yml`: eval/exec, command injection,
  insecure deserialization, Flask debug, hardcoded secrets, weak hashing, SQL string building,
  logging of user messages, **LLM prompt concatenation**, **unescaped model output**.
* **pip-audit** — checks pinned dependencies against PyPI/OSV advisories.
* **Trivy** — scans OS packages and Python packages inside the Docker image.
* **OWASP ZAP baseline** — passive DAST of the running container (headers, disclosure, cookies).
* **AI security tests** — instruction override, system-prompt disclosure (canary token),
  sensitive-data disclosure, unauthorized tool usage, output validation.

## Accessing security reports

1. Open the repository → **Actions** → select a *Security CI Pipeline* run.
2. The run **Summary** page shows the security summary table and the AI security report.
3. Scroll to **Artifacts** and download **`vulnfinbot-security-reports`** (kept 30 days). It contains
   `bandit-report.json`, `semgrep-report.json`, `dependency-report.json`, `trivy-report.json`,
   `zap-report.json` / `.html`, `ai-security-report.md`, `security-summary.md` and JUnit XML files.

## Identified vulnerabilities and remediation

The branch `security-test/vulnerable-demo` contains controlled insecure code (never merged to
`main`) to prove that each scanner detects its class of issue. Summary (details in the technical report):

| Tool | Before (vulnerable branch) | After (main) | Remediation |
|---|---|---|---|
| Bandit | 8 (2 HIGH) | 0 | removed eval / shell=True / pickle / md5 / hardcoded secrets |
| Semgrep | 9 (6 ERROR) | 0 | same + no prompt concatenation, no PII logging |
| pip-audit | 42 advisories | 0 | Flask 3.1.3, Werkzeug 3.1.9, Jinja2 3.1.6, gunicorn 27.0.1 |
| Trivy | 268 (57 HIGH) | 0 | Alpine base + `apk upgrade`, pip/setuptools removed, non-root user |
| OWASP ZAP | 3 warnings | 1 informational | security headers added |
| AI tests | 2 failed | 0 failed | output HTML escaping restored |

Recommendations: keep dependencies pinned and updated (Dependabot), rebuild images regularly,
keep secrets in GitHub Secrets, require the pipeline to pass before merge (branch protection),
and treat LLM guardrails as defence-in-depth rather than a guarantee.
