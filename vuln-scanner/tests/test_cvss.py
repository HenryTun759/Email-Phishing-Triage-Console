from app.cvss import score, severity_for

def test_cvss_known_vector():
    assert score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8

def test_zero_impact_is_none():
    assert score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0

def test_severity_bands():
    assert severity_for(3.9) == "low"
    assert severity_for(6.9) == "medium"
    assert severity_for(8.9) == "high"
    assert severity_for(9.8) == "critical"
