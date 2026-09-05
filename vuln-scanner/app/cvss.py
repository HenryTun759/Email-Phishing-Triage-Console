from math import ceil

# CVSS v3.1 base-score calculator for the vector families used by LabVuln.
WEIGHTS = {
    "AV": {"N": .85, "A": .62, "L": .55, "P": .2},
    "AC": {"L": .77, "H": .44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": .85, "R": .62},
    "C": {"H": .56, "L": .22, "N": 0},
    "I": {"H": .56, "L": .22, "N": 0},
    "A": {"H": .56, "L": .22, "N": 0},
}

def _roundup(x: float) -> float:
    return ceil(x * 10) / 10

def score(vector: str) -> float:
    parts = dict(item.split(":") for item in vector.removeprefix("CVSS:3.1/").split("/"))
    av, ac, pr, ui = (WEIGHTS[k][parts[k]] for k in ("AV", "AC", "PR", "UI"))
    pr = ({"L": .68, "H": .5}[parts["PR"]] if parts["PR"] in {"L", "H"} else .85) if parts.get("S") == "C" else pr
    scope_changed = parts.get("S") == "C"
    c, i, a = (WEIGHTS[k][parts[k]] for k in ("C", "I", "A"))
    impact = 1 - ((1-c) * (1-i) * (1-a))
    if not impact:
        return 0.0
    if scope_changed:
        impact_score = 7.52 * (impact - .029) - 3.25 * (impact - .02) ** 15
    else:
        impact_score = 6.42 * impact
    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        base = min(1.08 * (impact_score + exploitability), 10)
    else:
        base = min(impact_score + exploitability, 10)
    return _roundup(base)

def severity_for(score_value: float) -> str:
    if score_value == 0: return "none"
    if score_value < 4: return "low"
    if score_value < 7: return "medium"
    if score_value < 9: return "high"
    return "critical"

# Conservative vectors for the scanner's non-destructive findings.
VECTORS = {
    "http-server-header": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "http-headers:strict-transport-security": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "http-headers:content-security-policy": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "http-headers:x-content-type-options": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "http-headers:referrer-policy": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
}

def score_for_check(check_id: str) -> tuple[float, str, str]:
    vector = VECTORS.get(check_id, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
    value = score(vector)
    return value, severity_for(value), vector
