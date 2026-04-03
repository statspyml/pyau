def extract_severity(vuln: dict) -> dict:
    """Extract CVSS severity info from an OSV vuln entry.
    Returns a dict: {type, vector, score, label}.
    Prefers CVSS v4 over v3 if both are present.
    Falls back to database_specific.severity as label.
    """
    db_label = vuln.get("database_specific", {}).get("severity", "")

    for preferred in ("CVSS_V4", "CVSS_V3"):
        for entry in vuln.get("severity", []):
            if entry.get("type") == preferred:
                vector = entry.get("score", "")
                score, label = _cvss_score_and_label(vector)
                if label == "?" and db_label:
                    label = db_label.upper()
                return {"type": preferred, "vector": vector, "score": score, "label": label}

    if db_label:
        return {"type": "N/A", "vector": "", "score": "?", "label": db_label.upper()}

    return {"type": "N/A", "vector": "", "score": "N/A", "label": "UNKNOWN"}


def extract_fixed_versions(vuln: dict, pkg_name: str) -> list[str]:
    """Extract 'fixed' versions from affected[].ranges[].events.
    Only looks at ECOSYSTEM ranges matching the package name.
    """
    fixed: set[str] = set()
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != pkg_name.lower():
            continue
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _cvss_score_and_label(vector: str) -> tuple[str, str]:
    """Calculate numeric CVSS base score and severity label from a vector string.
    Uses the 'cvss' library if available, otherwise falls back to db_label.
    """
    try:
        from cvss import CVSS3, CVSS4  # type: ignore
        if vector.startswith("CVSS:4.0/"):
            c = CVSS4(vector)
        else:
            c = CVSS3(vector)
        score = str(c.base_score)
        label = c.severities()[0] if hasattr(c, "severities") else _label_from_score(float(score))
        return score, label.upper()
    except (ImportError, Exception):
        pass

    return "?", "?"


def _label_from_score(score: float) -> str:
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
