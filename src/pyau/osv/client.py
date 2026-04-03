import sys

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"


def query_osv_batch(packages: list[dict]) -> list[dict]:
    """Step 1: batch query — finds which packages have vulns.
    Returns one result per package (same order as input).
    Each result is {"vulns": [{"id": "GHSA-..."}, ...]} or {"vulns": []}.

    Note: the batch endpoint only returns vuln IDs — not full details.
    Use fetch_vuln_details() to get summary, severity, and fixed versions.
    """
    queries = [
        {
            "version": pkg["version"],
            "package": {"name": pkg["name"], "ecosystem": "PyPI"},
        }
        for pkg in packages
    ]

    print(f"\nQuerying OSV for {len(queries)} package(s)...")
    try:
        response = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error: OSV batch query failed: {e}", file=sys.stderr)
        sys.exit(1)

    return response.json().get("results", [])


def fetch_vuln_details(vuln_id: str) -> dict:
    """Step 2: fetch full vuln details from /v1/vulns/{id}.
    Returns summary, severity (CVSS vector), affected[], aliases, etc.
    """
    url = OSV_VULN_URL.format(vuln_id=vuln_id)
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()
