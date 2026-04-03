import sys

from pyau.osv.client import fetch_vuln_details
from pyau.severity import extract_fixed_versions, extract_severity


def process_results(packages: list[dict], results: list[dict]) -> list[dict]:
    """Zip packages with batch results, then fetch full details for each vuln.
    The batch endpoint only returns IDs — full data requires /v1/vulns/{id}.
    """
    findings = []
    for pkg, result in zip(packages, results):
        vuln_refs = result.get("vulns", [])
        if not vuln_refs:
            continue

        for vuln_ref in vuln_refs:
            vuln_id = vuln_ref.get("id", "N/A")
            print(f"  Fetching details for {vuln_id} ({pkg['name']})...")
            try:
                vuln = fetch_vuln_details(vuln_id)
            except Exception as e:
                print(f"  [WARN] Could not fetch {vuln_id}: {e}", file=sys.stderr)
                vuln = vuln_ref  # fallback to partial data

            findings.append({
                "package": pkg["name"],
                "version": pkg["version"],
                "vuln_id": vuln_id,
                "aliases": vuln.get("aliases", []),
                "summary": vuln.get("summary", "No summary available."),
                "severity": extract_severity(vuln),
                "fixed_versions": extract_fixed_versions(vuln, pkg["name"]),
            })

    return findings
