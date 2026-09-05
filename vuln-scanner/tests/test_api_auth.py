def test_protected_targets_endpoint_requires_auth(client):
    response = client.get("/api/targets")
    assert response.status_code == 401

def test_protected_scan_endpoint_requires_auth(client):
    response = client.get("/api/scans")
    assert response.status_code == 401

def test_health_remains_public(client):
    assert client.get("/health").status_code == 200
