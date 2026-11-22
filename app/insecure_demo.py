"""CONTROLLED INSECURE CODE - security-test branch only. Never merge to main.

Each block below is a known-bad pattern that the pipeline must detect.
"""

import hashlib
import logging
import pickle
import sqlite3
import subprocess

from flask import Blueprint, request

from .assistant import SYSTEM_PROMPT

demo = Blueprint("insecure_demo", __name__)
logger = logging.getLogger(__name__)

# [V1] Hardcoded credentials (Bandit B105, Semgrep hardcoded-secret)
OPENAI_API_KEY = "sk-demo-1234567890abcdefghijklmnop"
ADMIN_PASSWORD = "SuperSecret123!"


@demo.post("/api/calc")
def calc():
    # [V2] Code injection via eval (Bandit B307, Semgrep python-eval-usage)
    expression = request.get_json()["expr"]
    return {"result": eval(expression)}


@demo.post("/api/report")
def report():
    # [V3] Command injection (Bandit B602, Semgrep subprocess-shell-true)
    name = request.get_json()["name"]
    out = subprocess.check_output(f"cat reports/{name}", shell=True)
    return {"report": out.decode()}


@demo.post("/api/session")
def load_session():
    # [V4] Insecure deserialization (Bandit B301, Semgrep insecure-deserialization)
    return {"session": str(pickle.loads(request.data))}


@demo.get("/api/user")
def user():
    # [V5] SQL injection (Bandit B608, Semgrep sql-string-formatting)
    uid = request.args.get("id", "")
    cur = sqlite3.connect(":memory:").cursor()
    cur.execute("SELECT * FROM users WHERE id = '" + uid + "'")
    return {"rows": cur.fetchall()}


def password_hash(pw: str) -> str:
    # [V6] Weak hash (Bandit B324, Semgrep weak-hash-algorithm)
    return hashlib.md5(pw.encode()).hexdigest()


@demo.post("/api/unsafe-chat")
def unsafe_chat():
    message = request.get_json()["message"]
    # [V7] Sensitive data in logs (Semgrep logging-user-message)
    logger.info("user said: %s", message)
    # [V8] Prompt built by concatenation (Semgrep llm-prompt-concatenation)
    prompt = SYSTEM_PROMPT + "\nUser: " + message
    return {"prompt_preview": prompt[:50]}
