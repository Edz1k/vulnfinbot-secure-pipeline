"""Mini-VulnFinBot application factory."""

import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

MAX_MESSAGE_LENGTH = 1000
MAX_CONTENT_LENGTH = 16 * 1024  # 16 KB request body limit


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        MAX_MESSAGE_LENGTH=MAX_MESSAGE_LENGTH,
        JSON_SORT_KEYS=False,
    )
    if config:
        app.config.update(config)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    from .routes import bp

    app.register_blueprint(bp)
    _register_error_handlers(app)
    _register_security_headers(app)
    return app


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(HTTPException)
    def handle_http_error(err: HTTPException):
        # Generic JSON error: never return HTML error pages or internal details.
        return jsonify(error=err.name, status=err.code), err.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception):
        # Log the exception type only; the client gets a generic message, no stack trace.
        app.logger.error("Unhandled error: %s", type(err).__name__)
        return jsonify(error="Internal Server Error", status=500), 500


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Hide framework/server fingerprint.
        response.headers["Server"] = "vulnfinbot"
        return response
