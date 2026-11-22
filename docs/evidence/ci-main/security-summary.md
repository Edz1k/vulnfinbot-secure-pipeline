## Security summary

| Security Tool | Findings | Severity | Recommended Action |
|---|---|---|---|
| Bandit | 0 | 0 | Fix HIGH issues before merge; review MEDIUM/LOW, suppress only with justification (# nosec + reason). |
| Semgrep | 0 | 0 | ERROR rules block the pipeline; refactor insecure patterns (eval, shell=True, secrets). |
| pip-audit | 0 | 0 | Upgrade affected packages to the fixed versions and re-pin requirements.txt. |
| Trivy | 0 | 0 | Rebuild on the latest base image; upgrade fixable packages; track unfixed CVEs. |
| OWASP ZAP | 1 | INFO: 1 | Add/adjust security headers; review informational alerts; run full scan before release. |
| AI Security Tests | 1 | HIGH: 1 | Investigate any failed scenario; extend guardrails and the attack corpus. |

## Details

**Bandit**

- no findings

**Semgrep**

- no findings

**pip-audit**

- no findings

**Trivy**

- no findings

**OWASP ZAP**

- Non-Storable Content (INFO)

**AI Security Tests**

- 16 passed, 1 failed, 0 skipped

