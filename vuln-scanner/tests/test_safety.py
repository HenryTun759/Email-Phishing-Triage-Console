from app.scanner.safety import is_allowed_host

def test_loopback_is_allowed():
    assert is_allowed_host("127.0.0.1", False, False)

def test_public_requires_explicit_authorization(monkeypatch):
    monkeypatch.setattr("app.scanner.safety.resolve_ipv4", lambda host: "8.8.8.8")
    assert not is_allowed_host("example.invalid", False, True)
    assert is_allowed_host("example.invalid", True, True)

def test_public_without_authorization_is_denied(monkeypatch):
    monkeypatch.setattr("app.scanner.safety.resolve_ipv4", lambda host: "1.1.1.1")
    assert not is_allowed_host("example.invalid", True, False)
