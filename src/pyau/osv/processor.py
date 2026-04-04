import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from pyau.osv.client import fetch_vuln_details
from pyau.severity import extract_fixed_versions, extract_severity


def process_results(packages: list[dict], results: list[dict]) -> list[dict]:
    """Zip packages with batch results, then fetch full details for each vuln in parallel.
    The batch endpoint only returns IDs — full data requires /v1/vulns/{id}.
    """
    # Collect all (pkg, vuln_id, order_index) triples
    to_fetch: list[tuple[dict, str, int]] = []
    for pkg, result in zip(packages, results):
        for vuln_ref in result.get("vulns", []):
            to_fetch.append((pkg, vuln_ref.get("id", "N/A"), len(to_fetch)))

    if not to_fetch:
        return []

    print(f"  Fetching details for {len(to_fetch)} vulnerability(ies) in parallel...")

    ordered: list[dict | None] = [None] * len(to_fetch)

    with ThreadPoolExecutor() as executor:
        future_to_info = {
            executor.submit(fetch_vuln_details, vuln_id): (pkg, vuln_id, idx)
            for pkg, vuln_id, idx in to_fetch
        }
        for future in as_completed(future_to_info):
            pkg, vuln_id, idx = future_to_info[future]
            try:
                vuln = future.result()
            except Exception as e:
                print(f"  [WARN] Could not fetch {vuln_id}: {e}", file=sys.stderr)
                vuln = {"id": vuln_id}

            ordered[idx] = {
                "package": pkg["name"],
                "version": pkg["version"],
                "vuln_id": vuln_id,
                "aliases": vuln.get("aliases", []),
                "summary": vuln.get("summary", "No summary available."),
                "severity": extract_severity(vuln),
                "fixed_versions": extract_fixed_versions(vuln, pkg["name"]),
            }

    return [f for f in ordered if f is not None]
