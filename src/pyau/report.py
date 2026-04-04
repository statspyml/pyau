import json


def print_multiscan_report(scan_results: list[dict]) -> None:
    total_projects = len(scan_results)
    total_vulns = sum(r["vulnerabilities_found"] for r in scan_results)
    errors = [r for r in scan_results if r["error"]]

    print("\n" + "═" * 60)
    print("  pyau — Multiscan Report")
    print("═" * 60)
    print(f"  Projects scanned : {total_projects}")
    print(f"  Total vulns      : {total_vulns}")
    if errors:
        print(f"  Errors           : {len(errors)}")
    print("═" * 60)

    for result in scan_results:
        print(f"\n{'▶':>2} {result['name']}  [{result['path']}]")

        if result["error"]:
            print(f"    ! {result['error']}")
            continue

        print(f"    Dep file : {result['dep_file']}")
        print(f"    Packages : {result['packages_scanned']}  |  Vulns: {result['vulnerabilities_found']}")

        if not result["findings"]:
            print("    ✓ No known vulnerabilities found.")
            continue

        print("    " + "─" * 54)
        for f in result["findings"]:
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

            print(f"    Package  : {f['package']} {f['version']}")
            print(f"    Vuln ID  : {f['vuln_id']}")
            print(f"    Aliases  : {aliases}")
            print(f"    Severity : {sev_display}")
            print(f"    Fix in   : {fixed}")
            print(f"    Summary  : {f['summary']}")
            print("    " + "─" * 54)

    print()


def print_multiscan_json_report(scan_results: list[dict]) -> None:
    print(json.dumps(scan_results, indent=2))


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
