import json


def print_report(findings: list[dict], packages: list[dict]) -> None:
    total_pkgs = len(packages)
    total_vulns = len(findings)

    print("\n" + "═" * 60)
    print("  pyau — Vulnerability Report")
    print("═" * 60)
    print(f"  Packages scanned : {total_pkgs}")
    print(f"  Vulnerabilities  : {total_vulns}")
    print("═" * 60)

    if not findings:
        print("\n  ✓ No known vulnerabilities found.\n")
        return

    for f in findings:
        aliases = ", ".join(f["aliases"]) if f["aliases"] else "—"
        fixed = ", ".join(f.get("fixed_versions", [])) or "unknown"

        sev = f["severity"]
        if isinstance(sev, dict):
            score = sev.get("score", "?")
            label = sev.get("label", "UNKNOWN")
            sev_type = sev.get("type", "")
            score_str = f"{score} ({label})" if score not in ("N/A", "?") else label
            sev_display = f"{score_str}  [{sev_type}]"
        else:
            sev_display = str(sev)

        print(f"\n  Package   : {f['package']} {f['version']}")
        print(f"  Vuln ID   : {f['vuln_id']}")
        print(f"  Aliases   : {aliases}")
        print(f"  Severity  : {sev_display}")
        print(f"  Fix in    : {fixed}")
        print(f"  Summary   : {f['summary']}")
        print("  " + "─" * 56)

    print()


def print_json_report(findings: list[dict]) -> None:
    print(json.dumps(findings, indent=2))
