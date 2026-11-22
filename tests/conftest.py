import pytest

from app import create_app


@pytest.fixture()
def client(monkeypatch):
    # Tests always use the deterministic mock model.
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    app = create_app({"TESTING": True})
    return app.test_client()
