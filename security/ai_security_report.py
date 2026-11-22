"""Run the AI security scenarios and write reports/ai-security-report.md.

Usage:  python -m security.ai_security_report
"""

from __future__ import annotations

import datetime as dt
import os
import pathlib

from app import assistant
from tests.test_ai_security import CASES, LLM_CASES, run_case

OUT = pathlib.Path("reports/ai-security-report.md")


def _cell(text: str, limit: int = 140) -> str:
    text = " ".join(str(text).split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.replace("|", "\\|")


def main() -> int:
    rows, failed = [], 0
    llm_enabled = assistant.llm_enabled()
    for case in CASES + LLM_CASES:
        if case.level == "llm" and not llm_enabled:
            rows.append((case, "Not executed (no real LLM configured)", "SKIPPED"))
            continue
        model = assistant.get_model() if case.level == "llm" else None
        result = assistant.answer(case.input, model=model) if model else run_case(case)
        ok = case.check(result)
        failed += not ok
        actual = result.response
        if result.blocked_tools:
            actual += f" (blocked tools: {', '.join(result.blocked_tools)})"
        if result.flags:
            actual += f" [flags: {', '.join(result.flags)}]"
        rows.append((case, actual, "PASS" if ok else "FAIL"))

    passed = sum(r[2] == "PASS" for r in rows)
    skipped = sum(r[2] == "SKIPPED" for r in rows)
    lines = [
        "# Mini-VulnFinBot — AI Security Test Report",
        "",
        f"Generated: {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}  ",
        f"Model backend for LLM-xx: {assistant.get_model().name if llm_enabled else 'none (LLM-xx skipped)'}; AI-xx use MockModel  ",
        f"Result: **{passed} passed, {failed} failed, {skipped} skipped** of {len(rows)} scenarios",
        "",
        "## Scope and limitations",
        "",
        "* **App-level tests (AI-xx)** run against a deterministic mock model and a *fake malicious model*.",
        "  They verify controls implemented in application code: input guardrails, tool allow-listing,",
        "  output validation (escaping, secret redaction, canary leak detection, length limit).",
        "* They **do not** prove that a language model resists prompt injection. That requires the",
        "  **LLM-xx** scenarios, which run only against a real model (Ollama container with an open-weights model in CI) in a controlled",
        "  test environment and use phrasing that bypasses the regex filter on purpose.",
        "",
        "## Results",
        "",
        "| ID | Scenario | Security risk | Test input | Expected behavior | Actual behavior | Result | Recommended mitigation |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for case, actual, status in rows:
        icon = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "SKIPPED": "⏭ SKIPPED"}[status]
        lines.append(
            f"| {case.id} | {_cell(case.category)} | {_cell(case.risk)} | {_cell(case.input, 90)} | "
            f"{_cell(case.expected)} | {_cell(actual)} | {icon} | {_cell(case.mitigation)} |"
        )
    lines += [
        "",
        "## Residual risks and recommendations",
        "",
        "1. Regex guardrails are bypassable (paraphrasing, other languages, encodings). Treat them as a",
        "   first filter only; rely on the model's instruction hierarchy plus output validation.",
        "2. Keep secrets and customer data out of the model context entirely — the model cannot leak what it never sees.",
        "3. Tools are authorized by application code per user role; privileged actions need authenticated",
        "   users and explicit human confirmation.",
        "4. Run the LLM-xx scenarios on every model or prompt change, and extend the corpus with",
        "   new attack patterns (indirect injection via documents, multi-turn attacks).",
        "",
    ]
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT}: {passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
