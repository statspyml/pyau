import json

from pyau.severity import meets_threshold, severity_label


def print_fix_report(fix_results: list[dict]) -> None:
    """Exibe o resultado do dry-run de fix para cada pacote."""
    total = len(fix_results)
    resolved = sum(1 for r in fix_results if r["success"] is True)
    conflicts = sum(1 for r in fix_results if r["success"] is False)
    no_fix    = sum(1 for r in fix_results if r["success"] is None)

    print("\n" + "═" * 60)
    print("  pyau — Fix Dry-run Report")
    print("═" * 60)
    print(f"  Packages checked : {total}")
    print(f"  Resolves cleanly : {resolved}")
    print(f"  Conflicts        : {conflicts}")
    print(f"  No fix available : {no_fix}")
    print("═" * 60)

    for r in fix_results:
        package     = r["package"]
        fix_version = r.get("fix_version") or "?"
        success     = r["success"]
        output      = r.get("output", "").strip()

        if success is True:
            status = "✅  resolves cleanly"
        elif success is False:
            first_line = output.splitlines()[0] if output else "conflict"
            status = f"❌  {first_line}"
        else:
            status = "⚠️   no fix version available"

        print(f"\n  {package:<20} →  {fix_version:<12}  {status}")

    print()


def print_multiscan_report(scan_results: list[dict], filter_threshold: str | None = None) -> None:
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
            _print_finding(f, indent=4)

    _print_filter_section_multiscan(scan_results, filter_threshold)
    print()


def print_multiscan_json_report(scan_results: list[dict]) -> None:
    print(json.dumps(scan_results, indent=2))


def print_report(findings: list[dict], packages: list[dict], filter_threshold: str | None = None) -> None:
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
        _print_filter_section(findings, filter_threshold)
        return

    for f in findings:
        print()
        _print_finding(f, indent=2)

    _print_filter_section(findings, filter_threshold)
    print()


def print_json_report(findings: list[dict]) -> None:
    print(json.dumps(findings, indent=2))


# ── helpers ───────────────────────────────────────────────────────────────────

def _print_finding(f: dict, indent: int = 2) -> None:
    pad = " " * indent
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

    print(f"{pad}Package  : {f['package']} {f['version']}")
    print(f"{pad}Vuln ID  : {f['vuln_id']}")
    print(f"{pad}Aliases  : {aliases}")
    print(f"{pad}Severity : {sev_display}")
    print(f"{pad}Fix in   : {fixed}")
    print(f"{pad}Summary  : {f['summary']}")
    print(pad + "─" * (58 - indent))


def _print_filter_section(findings: list[dict], threshold: str | None) -> None:
    if threshold is None:
        return

    label = threshold.upper()
    matched = [f for f in findings if meets_threshold(f, label)]

    print("\n" + "═" * 60)
    print(f"  Filter: {label} and above  ({len(matched)} finding(s))")
    print("═" * 60)

    if not matched:
        print(f"\n  No findings at {label} level or above.\n")
        return

    for f in matched:
        print()
        _print_finding(f, indent=2)


def _print_filter_section_multiscan(scan_results: list[dict], threshold: str | None) -> None:
    if threshold is None:
        return

    label = threshold.upper()
    matched: list[tuple[str, dict]] = []
    for result in scan_results:
        for f in result.get("findings", []):
            if meets_threshold(f, label):
                matched.append((result["name"], f))

    print("\n" + "═" * 60)
    print(f"  Filter: {label} and above  ({len(matched)} finding(s))")
    print("═" * 60)

    if not matched:
        print(f"\n  No findings at {label} level or above.\n")
        return

    current_project = None
    for project_name, f in matched:
        if project_name != current_project:
            current_project = project_name
            print(f"\n  {'▶'} {project_name}")
        print()
        _print_finding(f, indent=4)
