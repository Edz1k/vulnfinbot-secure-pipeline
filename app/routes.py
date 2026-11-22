"""HTTP routes for Mini-VulnFinBot."""

import logging

from flask import Blueprint, current_app, jsonify, request

from .assistant import answer

bp = Blueprint("api", __name__)
logger = logging.getLogger(__name__)


def _error(message: str, status: int):
    return jsonify(error=message, status=status), status


@bp.get("/")
def index():
    return jsonify(service="Mini-VulnFinBot", endpoints=["GET /health", "POST /api/chat"])


@bp.get("/health")
def health():
    return jsonify(status="healthy")


@bp.post("/api/chat")
def chat():
    if not request.is_json:
        return _error("Content-Type must be application/json", 415)

    data = request.get_json(silent=True)
    if data is None:
        return _error("Invalid JSON body", 400)
    if not isinstance(data, dict):
        return _error("JSON body must be an object", 400)
    if "message" not in data:
        return _error("Field 'message' is required", 400)

    message = data["message"]
    if not isinstance(message, str):
        return _error("Field 'message' must be a string", 400)

    message = message.strip()
    if not message:
        return _error("Field 'message' must not be empty", 400)

    max_len = current_app.config["MAX_MESSAGE_LENGTH"]
    if len(message) > max_len:
        return _error(f"Field 'message' must be at most {max_len} characters", 413)

    # Log metadata only - never the user's message content.
    logger.info("chat request received (len=%d)", len(message))

    result = answer(message)
    return jsonify(response=result.response)
