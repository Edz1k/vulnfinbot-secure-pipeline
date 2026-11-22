"""Functional tests for the REST API."""


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "healthy"}


def test_successful_chat_request(client):
    resp = client.post("/api/chat", json={"message": "How can I manage my monthly budget?"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "response" in body
    assert "income and expenses" in body["response"]


def test_empty_message_rejected(client):
    resp = client.post("/api/chat", json={"message": ""})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_whitespace_only_message_rejected(client):
    resp = client.post("/api/chat", json={"message": "   \n\t "})
    assert resp.status_code == 400


def test_missing_message_rejected(client):
    resp = client.post("/api/chat", json={"text": "hello"})
    assert resp.status_code == 400
    assert "required" in resp.get_json()["error"]


def test_invalid_json_handled(client):
    resp = client.post("/api/chat", data="{not valid json", content_type="application/json")
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["error"] == "Invalid JSON body"
    assert "Traceback" not in resp.get_data(as_text=True)


def test_wrong_content_type_rejected(client):
    resp = client.post("/api/chat", data="message=hi", content_type="application/x-www-form-urlencoded")
    assert resp.status_code == 415


def test_too_long_message_rejected(client):
    resp = client.post("/api/chat", json={"message": "a" * 1001})
    assert resp.status_code == 413


def test_max_length_message_accepted(client):
    resp = client.post("/api/chat", json={"message": "b" * 1000})
    assert resp.status_code == 200


def test_oversized_body_rejected(client):
    resp = client.post("/api/chat", data='{"message": "' + "x" * 20000 + '"}', content_type="application/json")
    assert resp.status_code == 413
    assert resp.is_json


def test_unexpected_message_types_rejected(client):
    for value in (123, 1.5, True, None, ["a"], {"a": 1}):
        resp = client.post("/api/chat", json={"message": value})
        assert resp.status_code == 400, value


def test_non_object_json_rejected(client):
    resp = client.post("/api/chat", json=["message", "hi"])
    assert resp.status_code == 400


def test_unknown_route_returns_json_404(client):
    resp = client.get("/does-not-exist")
    assert resp.status_code == 404
    assert resp.is_json


def test_wrong_method_returns_json_405(client):
    resp = client.get("/api/chat")
    assert resp.status_code == 405
    assert resp.is_json


def test_internal_error_does_not_leak_details(client, monkeypatch):
    import app.routes as routes

    def boom(_message):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(routes, "answer", boom)
    client.application.config["PROPAGATE_EXCEPTIONS"] = False
    resp = client.post("/api/chat", json={"message": "hi"})
    assert resp.status_code == 500
    text = resp.get_data(as_text=True)
    assert "secret internal detail" not in text
    assert "Traceback" not in text


def test_security_headers_present(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers


def test_user_message_not_logged(client, caplog):
    secret = "my card is 4111 1111 1111 1111"
    with caplog.at_level("INFO"):
        client.post("/api/chat", json={"message": secret})
    assert secret not in caplog.text
    assert "4111" not in caplog.text
