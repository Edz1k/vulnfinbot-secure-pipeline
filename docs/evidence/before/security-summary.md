## Security summary

| Security Tool | Findings | Severity | Recommended Action |
|---|---|---|---|
| Bandit | 8 | HIGH: 2, MEDIUM: 3, LOW: 3 | Fix HIGH issues before merge; review MEDIUM/LOW, suppress only with justification (# nosec + reason). |
| Semgrep | 9 | HIGH: 6, MEDIUM: 3 | ERROR rules block the pipeline; refactor insecure patterns (eval, shell=True, secrets). |
| pip-audit | 42 | UNRATED: 42 | Upgrade affected packages to the fixed versions and re-pin requirements.txt. |
| Trivy | 268 | HIGH: 57, MEDIUM: 119, LOW: 85, UNKNOWN: 7 | Rebuild on the latest base image; upgrade fixable packages; track unfixed CVEs. |
| OWASP ZAP | 3 | LOW: 2, INFO: 1 | Add/adjust security headers; review informational alerts; run full scan before release. |
| AI Security Tests | 2 | HIGH: 2 | Investigate any failed scenario; extend guardrails and the attack corpus. |

## Details

**Bandit**

- B105 hardcoded_password_string
- B301 blacklist
- B307 blacklist
- B324 hashlib
- B403 blacklist
- B404 blacklist
- B602 subprocess_popen_with_shell_equals_true
- B608 hardcoded_sql_expressions

**Semgrep**

- hardcoded-secret
- insecure-deserialization
- llm-prompt-concatenation
- logging-user-message
- python-eval-usage
- sql-string-formatting
- subprocess-shell-true
- weak-hash-algorithm

**pip-audit**

- flask==2.2.2: PYSEC-2023-62 (fix: 2.2.5, 2.3.2)
- flask==2.2.2: PYSEC-2023-62 (fix: 2.2.5, 2.3.2)
- flask==2.2.2: PYSEC-2026-2151 (fix: 3.1.3)
- flask==2.2.2: PYSEC-2026-2151 (fix: 3.1.3)
- werkzeug==2.2.2: PYSEC-2023-57 (fix: 2.2.3)
- werkzeug==2.2.2: PYSEC-2023-58 (fix: 2.2.3)
- werkzeug==2.2.2: PYSEC-2023-58 (fix: 2.2.3)
- werkzeug==2.2.2: PYSEC-2023-57 (fix: 2.2.3)
- werkzeug==2.2.2: PYSEC-2023-221 (fix: 2.3.8, 3.0.1)
- werkzeug==2.2.2: PYSEC-2023-221 (fix: 2.3.8, 3.0.1)
- werkzeug==2.2.2: PYSEC-2026-2043 (fix: 3.0.3)
- werkzeug==2.2.2: PYSEC-2026-2045 (fix: 3.0.6)
- werkzeug==2.2.2: PYSEC-2026-1860 (fix: 3.0.6)
- werkzeug==2.2.2: PYSEC-2026-2046 (fix: 3.1.4)
- werkzeug==2.2.2: PYSEC-2026-2044 (fix: 3.1.5)
- werkzeug==2.2.2: PYSEC-2026-2320 (fix: 3.1.6)
- werkzeug==2.2.2: PYSEC-2026-2046 (fix: 3.1.4)
- werkzeug==2.2.2: PYSEC-2026-2045 (fix: 3.0.6)
- werkzeug==2.2.2: PYSEC-2026-2044 (fix: 3.1.5)
- werkzeug==2.2.2: PYSEC-2026-2043 (fix: 3.0.3)
- werkzeug==2.2.2: PYSEC-2026-2320 (fix: 3.1.6)
- werkzeug==2.2.2: PYSEC-2026-3417 (fix: 3.0.6)
- werkzeug==2.2.2: PYSEC-2026-4312 (fix: 3.1.9)
- jinja2==3.1.2: PYSEC-2026-1473 (fix: 3.1.3)
- jinja2==3.1.2: PYSEC-2026-1474 (fix: 3.1.4)
- jinja2==3.1.2: PYSEC-2026-1475 (fix: 3.1.5)
- jinja2==3.1.2: PYSEC-2026-1472 (fix: 3.1.5)
- jinja2==3.1.2: PYSEC-2026-1471 (fix: 3.1.6)
- jinja2==3.1.2: PYSEC-2026-1473 (fix: 3.1.3)
- jinja2==3.1.2: PYSEC-2026-1471 (fix: 3.1.6)
- jinja2==3.1.2: PYSEC-2026-1474 (fix: 3.1.4)
- jinja2==3.1.2: PYSEC-2026-1475 (fix: 3.1.5)
- jinja2==3.1.2: PYSEC-2026-1472 (fix: 3.1.5)
- gunicorn==20.1.0: PYSEC-2026-1434 (fix: 22.0.0)
- gunicorn==20.1.0: PYSEC-2026-1433 (fix: 22.0.0)
- gunicorn==20.1.0: PYSEC-2026-1434 (fix: 22.0.0)
- gunicorn==20.1.0: PYSEC-2026-1433 (fix: 22.0.0)
- setuptools==70.0.0: PYSEC-2025-49 (fix: 78.1.1)
- setuptools==70.0.0: PYSEC-2025-49 (fix: 78.1.1)
- setuptools==70.0.0: PYSEC-2026-3447 (fix: 83.0.0)

**Trivy**

- Flask CVE-2023-30861 (HIGH, fixed: 2.3.2, 2.2.5)
- Werkzeug CVE-2023-25577 (HIGH, fixed: 2.2.3)
- Werkzeug CVE-2024-34069 (HIGH, fixed: 3.0.3)
- bsdutils CVE-2026-76642 (HIGH, fixed: no fix)
- bsdutils CVE-2026-78408 (HIGH, fixed: no fix)
- bsdutils CVE-2026-78409 (HIGH, fixed: no fix)
- bsdutils CVE-2026-78410 (HIGH, fixed: no fix)
- gunicorn CVE-2024-1135 (HIGH, fixed: 22.0.0)
- gunicorn CVE-2024-6827 (HIGH, fixed: 22.0.0)
- libacl1 CVE-2026-54369 (HIGH, fixed: no fix)
- libblkid1 CVE-2026-76642 (HIGH, fixed: no fix)
- libblkid1 CVE-2026-78408 (HIGH, fixed: no fix)
- libblkid1 CVE-2026-78409 (HIGH, fixed: no fix)
- libblkid1 CVE-2026-78410 (HIGH, fixed: no fix)
- liblastlog2-2 CVE-2026-76642 (HIGH, fixed: no fix)
- liblastlog2-2 CVE-2026-78408 (HIGH, fixed: no fix)
- liblastlog2-2 CVE-2026-78409 (HIGH, fixed: no fix)
- liblastlog2-2 CVE-2026-78410 (HIGH, fixed: no fix)
- libmount1 CVE-2026-76642 (HIGH, fixed: no fix)
- libmount1 CVE-2026-78408 (HIGH, fixed: no fix)
- libmount1 CVE-2026-78409 (HIGH, fixed: no fix)
- libmount1 CVE-2026-78410 (HIGH, fixed: no fix)
- libncursesw6 CVE-2025-69720 (HIGH, fixed: no fix)
- libsmartcols1 CVE-2026-76642 (HIGH, fixed: no fix)
- libsmartcols1 CVE-2026-78408 (HIGH, fixed: no fix)
- libsmartcols1 CVE-2026-78409 (HIGH, fixed: no fix)
- libsmartcols1 CVE-2026-78410 (HIGH, fixed: no fix)
- libsqlite3-0 CVE-2026-119373 (HIGH, fixed: no fix)
- libsqlite3-0 CVE-2026-119374 (HIGH, fixed: no fix)
- libsqlite3-0 CVE-2026-119379 (HIGH, fixed: no fix)
- libssl3t64 CVE-2026-124709 (HIGH, fixed: no fix)
- libsystemd0 CVE-2026-16742 (HIGH, fixed: no fix)
- libtinfo6 CVE-2025-69720 (HIGH, fixed: no fix)
- libudev1 CVE-2026-16742 (HIGH, fixed: no fix)
- libuuid1 CVE-2026-76642 (HIGH, fixed: no fix)
- libuuid1 CVE-2026-78408 (HIGH, fixed: no fix)
- libuuid1 CVE-2026-78409 (HIGH, fixed: no fix)
- libuuid1 CVE-2026-78410 (HIGH, fixed: no fix)
- login CVE-2026-76642 (HIGH, fixed: no fix)
- login CVE-2026-78408 (HIGH, fixed: no fix)

**OWASP ZAP**

- Cross-Origin-Resource-Policy Header Missing or Invalid (LOW)
- Storable and Cacheable Content (INFO)
- X-Content-Type-Options Header Missing (LOW)

**AI Security Tests**

- 12 passed, 2 failed, 3 skipped

