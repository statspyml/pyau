#!/usr/bin/env python3
"""pyaudit - A pip-audit inspired vulnerability scanner using the OSV API.
Parses requirements.txt, pyproject.toml or poetry.lock and checks for known vulnerabilities.
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install it with: pip install requests")
    sys.exit(1)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


# ──────────────────────────────────────────────
# Parsers
# ──────────────────────────────────────────────

def parse_requirements_txt(path: Path) -> list[dict]:
    """Parse a requirements.txt file and return a list of {name, version} dicts.
    Handles:
      - name==version
      - name>=version (uses the first version found)
      - Comments and blank lines
      - Extras like package[extra]==version
    """
    packages = []
    for line in path.read_text().splitlines():
        line = line.strip()

        # Skip comments, blank lines, and options (e.g. -r, -i, --index-url)
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Strip inline comments
        line = line.split("#")[0].strip()

        # Match name (with optional extras) followed by a version specifier
        match = re.match(
            r"^([A-Za-z0-9_\-]+)(?:\[.*?\])?[><=!~]+\s*([^\s,;]+)",
            line,
        )
        if match:
            name, version = match.group(1), match.group(2)
            # Normalise: strip leading zeros, qualifiers like .post1, etc.
            packages.append({"name": name, "version": version})
        else:
            # Package without a pinned version — we can't query without a version
            bare_match = re.match(r"^([A-Za-z0-9_\-]+)", line)
            if bare_match:
                print(
                    f"  [WARN] Skipping '{bare_match.group(1)}' — no version pinned.",
                    file=sys.stderr,
                )

    return packages


def parse_pyproject_toml(path: Path) -> list[dict]:
    """Parse a pyproject.toml and return a list of {name, version} dicts.

    Supports two formats:
      - PEP 621 / modern Poetry: [project] dependencies = ["requests (>=2.33.1,<3.0.0)", ...]
      - Poetry classic:          [tool.poetry.dependencies] requests = ">=2.33.1,<3.0.0"
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # pip install tomli
        except ImportError:
            print(
                "Error: parsing pyproject.toml requires Python 3.11+ or 'tomli'.\n"
                "Install with: pip install tomli",
                file=sys.stderr,
            )
            sys.exit(1)

    with path.open("rb") as f:
        data = tomllib.load(f)

    packages = []

    # ── Format 1: PEP 621 [project] ──────────────────────────────────────────
    # dependencies is a list of PEP 508 strings:
    #   "requests (>=2.33.1,<3.0.0)"  or  "requests>=2.33.1"
    pep621_deps = data.get("project", {}).get("dependencies", [])
    if pep621_deps:
        print("  Format: PEP 621 [project]")
        for dep_str in pep621_deps:
            # Parse PEP 508: name (optional extras) [spaces] specifier
            # e.g. "requests (>=2.33.1,<3.0.0)" or "tornado (==6.5.4)"
            match = re.match(
                r"^([A-Za-z0-9_\-]+)"          # package name
                r"(?:\[.*?\])?"                 # optional extras
                r"\s*[\(\s]*"                   # optional opening paren / space
                r"[><=!~]*\s*"                  # version specifier operator
                r"(\d+\.\d+(?:\.\d+)*)",        # first version number
                dep_str.strip(),
            )
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})
            else:
                bare = re.match(r"^([A-Za-z0-9_\-]+)", dep_str.strip())
                if bare:
                    print(
                        f"  [WARN] Skipping '{bare.group(1)}' — could not resolve version.",
                        file=sys.stderr,
                    )

    # ── Format 2: Poetry classic [tool.poetry.dependencies] ──────────────────
    poetry_section = data.get("tool", {}).get("poetry", {})
    dep_sections = {
        "dependencies": poetry_section.get("dependencies", {}),
        "dev-dependencies": poetry_section.get("dev-dependencies", {}),
        **{
            f"group:{name}": group.get("dependencies", {})
            for name, group in poetry_section.get("group", {}).items()
        },
    }
    has_poetry_deps = any(dep_sections.values())

    if has_poetry_deps:
        print("  Format: Poetry classic [tool.poetry]")
        for section, deps in dep_sections.items():
            for pkg_name, spec in deps.items():
                if pkg_name.lower() == "python":
                    continue

                version = None
                if isinstance(spec, str):
                    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", spec)
                    if m:
                        version = m.group(1)
                elif isinstance(spec, dict):
                    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", spec.get("version", ""))
                    if m:
                        version = m.group(1)

                if version:
                    packages.append({"name": pkg_name, "version": version})
                else:
                    print(
                        f"  [WARN] Skipping '{pkg_name}' in [{section}] — could not resolve version.",
                        file=sys.stderr,
                    )

    if not packages:
        print(
            "  [WARN] No dependencies found. "
            "Expected [project].dependencies (PEP 621) or [tool.poetry.dependencies].",
            file=sys.stderr,
        )

    return packages



def _load_toml(path: Path) -> dict:
    """Load a TOML file using tomllib (3.11+) or tomli fallback."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            print(
                "Error: requires Python 3.11+ or 'tomli'.\n"
                "Install with: pip install tomli",
                file=sys.stderr,
            )
            sys.exit(1)
    with path.open("rb") as f:
        return tomllib.load(f)


def parse_poetry_lock(
    path: Path,
    groups: list[str] | None = None,
    direct_names: set[str] | None = None,
) -> list[dict]:
    """Parse a poetry.lock file and return a list of {name, version, groups} dicts.

    Args:
        path:         Path to poetry.lock
        groups:       If set, only include packages belonging to these groups
                      (e.g. ["main"], ["main", "dev"]).
                      Defaults to ["main"] when None.
        direct_names: If set, only include packages whose normalised name is in
                      this set (used by --direct-only to skip transitive deps).

    """
    data = _load_toml(path)
    active_groups = set(groups) if groups else {"main"}

    packages = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        pkg_groups = set(pkg.get("groups", ["main"]))

        if not name or not version:
            print(f"  [WARN] Skipping malformed entry: {pkg}", file=sys.stderr)
            continue

        # Group filter
        if not pkg_groups.intersection(active_groups):
            continue

        # Direct-only filter
        if direct_names is not None:
            normalised = name.lower().replace("-", "_")
            if normalised not in direct_names:
                continue

        packages.append({"name": name, "version": version, "groups": sorted(pkg_groups)})

    return packages


def _direct_names_from_pyproject(pyproject_path: Path) -> set[str]:
    """Extract the set of directly declared dependency names from pyproject.toml.
    Supports both PEP 621 [project] and Poetry classic [tool.poetry] formats.
    Returns normalised names (lowercase, hyphens → underscores).
    """
    data = _load_toml(pyproject_path)
    names: set[str] = set()

    # PEP 621
    for dep_str in data.get("project", {}).get("dependencies", []):
        m = re.match(r"^([A-Za-z0-9_\-]+)", dep_str.strip())
        if m:
            names.add(m.group(1).lower().replace("-", "_"))

    # Poetry classic
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name in poetry_deps:
        if name.lower() != "python":
            names.add(name.lower().replace("-", "_"))

    return names


def parse_uv_lock(
    path: Path,
    direct_names: set[str] | None = None,
) -> list[dict]:
    """Parse a uv.lock file and return a list of {name, version} dicts.

    uv.lock structure (TOML):
        version = 1

        [[package]]
        name = "requests"
        version = "2.31.0"
        source = { registry = "https://pypi.org/simple" }
        ...

    Key differences from poetry.lock:
      - No `groups` field per package — group info lives in pyproject.toml
      - Packages with source = { editable = "." } or { path = "..." } are the
        project itself or local deps — skip them, they're not PyPI packages
      - `version` may be missing for virtual/editable entries
    """
    data = _load_toml(path)

    packages = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", {})

        # Skip the project itself and local path dependencies
        if "editable" in source or "path" in source or "git" in source:
            continue

        if not name or not version:
            continue

        # Direct-only filter
        if direct_names is not None:
            normalised = name.lower().replace("-", "_")
            if normalised not in direct_names:
                continue

        packages.append({"name": name, "version": version, "groups": ["main"]})

    return packages

def detect_and_parse(file_path: str, groups: list[str] | None = None, direct_only: bool = False) -> list[dict]:
    path = Path(file_path)
    if not path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    # ── uv.lock ──────────────────────────────────────────────────────────
    if path.name == "uv.lock":
        direct_names = None
        if direct_only:
            pyproject = path.parent / "pyproject.toml"
            if pyproject.exists():
                direct_names = _direct_names_from_pyproject(pyproject)
                print(f"Detected: uv.lock — direct-only mode ({len(direct_names)} direct deps)")
            else:
                print("Detected: uv.lock — [WARN] --direct-only requested but no pyproject.toml found, auditing all")
        else:
            print("Detected: uv.lock (all resolved packages)")
        return parse_uv_lock(path, direct_names=direct_names)

    # ── poetry.lock ───────────────────────────────────────────────────────
    if path.name == "poetry.lock":
        direct_names = None
        if direct_only:
            pyproject = path.parent / "pyproject.toml"
            if pyproject.exists():
                direct_names = _direct_names_from_pyproject(pyproject)
                print(f"Detected: poetry.lock — direct-only mode ({len(direct_names)} direct deps)")
            else:
                print("Detected: poetry.lock — [WARN] --direct-only requested but no pyproject.toml found, auditing all")
        else:
            print("Detected: poetry.lock (all resolved packages)")
        return parse_poetry_lock(path, groups=groups, direct_names=direct_names)

    # ── pyproject.toml ────────────────────────────────────────────────────
    if path.name == "pyproject.toml":
        # Prefer uv.lock over poetry.lock if both exist
        uv_lock = path.parent / "uv.lock"
        poetry_lock = path.parent / "poetry.lock"

        if uv_lock.exists():
            direct_names = _direct_names_from_pyproject(path) if direct_only else None
            label = f"direct-only mode ({len(direct_names)} direct deps)" if direct_only else "all resolved packages"
            print(f"Detected: pyproject.toml — uv.lock found, auditing {label}")
            return parse_uv_lock(uv_lock, direct_names=direct_names)

        if poetry_lock.exists():
            direct_names = _direct_names_from_pyproject(path) if direct_only else None
            label = f"direct-only mode ({len(direct_names)} direct deps)" if direct_only else "all resolved packages"
            print(f"Detected: pyproject.toml — poetry.lock found, auditing {label}")
            return parse_poetry_lock(poetry_lock, groups=groups, direct_names=direct_names)

        print("Detected: pyproject.toml (no lockfile found, using declared version ranges)")
        return parse_pyproject_toml(path)

    # ── requirements.txt ──────────────────────────────────────────────────
    if path.name.endswith(".txt") or "requirements" in path.name.lower():
        print("Detected: requirements.txt")
        return parse_requirements_txt(path)

    print(
        f"Error: Unrecognised file '{path.name}'. "
        "Expected uv.lock, poetry.lock, pyproject.toml, or requirements.txt.",
        file=sys.stderr,
    )
    sys.exit(1)


# ──────────────────────────────────────────────
# OSV API
# ──────────────────────────────────────────────

def build_osv_queries(packages: list[dict]) -> list[dict]:
    """Build the list of query objects for the OSV /v1/querybatch endpoint."""
    return [
        {
            "version": pkg["version"],
            "package": {
                "name": pkg["name"],
                "ecosystem": "PyPI",
            },
        }
        for pkg in packages
    ]


OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"


def query_osv_batch(packages: list[dict]) -> list[dict]:
    """Step 1: batch query to find which packages have vulns (returns only vuln ids).
    Each result corresponds to the package at the same index in `packages`.
    """
    queries = build_osv_queries(packages)
    payload = {"queries": queries}

    print(f"\nQuerying OSV for {len(queries)} package(s)...")
    response = requests.post(OSV_BATCH_URL, json=payload, timeout=30)
    response.raise_for_status()

    data = response.json()
    return data.get("results", [])


def fetch_vuln_details(vuln_id: str) -> dict:
    """Step 2: fetch full vuln details (summary, severity, affected/fixed versions)
    from /v1/vulns/{id} — the batch endpoint only returns ids.
    """
    url = OSV_VULN_URL.format(vuln_id=vuln_id)
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


# ──────────────────────────────────────────────
# Result processing
# ──────────────────────────────────────────────

def process_results(packages: list[dict], results: list[dict]) -> list[dict]:
    """Zip packages with batch results, then fetch full details for each vuln.
    The batch endpoint only returns ids; full data requires /v1/vulns/{id}.
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
                vuln = vuln_ref  # fall back to the partial data from batch

            findings.append(
                {
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "vuln_id": vuln_id,
                    "aliases": vuln.get("aliases", []),
                    "summary": vuln.get("summary", "No summary available."),
                    "severity": _extract_severity(vuln),  # dict: type, vector, score, label
                    "fixed_versions": _extract_fixed_versions(vuln, pkg["name"]),
                },
            )
    return findings


def _extract_fixed_versions(vuln: dict, pkg_name: str) -> list[str]:
    """Extract fixed versions from affected[].ranges[].events.
    Only looks at ECOSYSTEM ranges for the matching package name.
    Returns a sorted list, e.g. ["6.4.2", "6.5.0"].
    """
    fixed = set()
    for affected in vuln.get("affected", []):
        affected_name = affected.get("package", {}).get("name", "")
        if affected_name.lower() != pkg_name.lower():
            continue
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _cvss_score_and_label(vector: str) -> tuple[str, str]:
    """Calculate the numeric CVSS base score and severity label from a vector string.
    Supports CVSS v3.x (CVSS:3.0/... and CVSS:3.1/...) and CVSS v4.0.
    Falls back to parsing the vector manually if the 'cvss' library is unavailable.
    Returns (score_str, label) e.g. ("6.1", "MEDIUM").
    """
    try:
        from cvss import CVSS3, CVSS4
        if vector.startswith("CVSS:4.0/"):
            c = CVSS4(vector)
        else:
            c = CVSS3(vector)
        score = str(c.base_score)
        label = c.severities()[0] if hasattr(c, "severities") else _label_from_score(float(score))
        return score, label.upper()
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: try to read BV (base score) from CVSS4, or compute naively
    # Just derive label from the vector's impact indicators heuristically
    return "?", _label_from_vector(vector)


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


def _label_from_vector(vector: str) -> str:
    """Rough severity label when we can't compute the actual score."""
    # Use database_specific.severity if embedded in the vuln object — not available
    # here, so we fall back to a heuristic based on the vector components.
    if "AV:N" in vector and "PR:N" in vector and "UI:N" in vector:
        if "VA:H" in vector or "A:H" in vector:
            return "HIGH"
        return "MEDIUM"
    return "MEDIUM"


def _extract_severity(vuln: dict) -> dict:
    """Extract CVSS severity info from an OSV vuln entry.
    Returns a dict with: type, vector, score, label.
    Prefers CVSS v4 over v3 if both are present.
    Also checks database_specific.severity as a label fallback.
    """
    db_label = vuln.get("database_specific", {}).get("severity", "")

    candidates = vuln.get("severity", [])
    # Prefer CVSS4, then CVSS3
    for preferred in ("CVSS_V4", "CVSS_V3"):
        for entry in candidates:
            if entry.get("type") == preferred:
                vector = entry.get("score", "")
                score, label = _cvss_score_and_label(vector)
                if label == "?" and db_label:
                    label = db_label.upper()
                return {
                    "type": preferred,
                    "vector": vector,
                    "score": score,
                    "label": label,
                }

    # No CVSS vector — use db_label if available
    if db_label:
        return {"type": "N/A", "vector": "", "score": "?", "label": db_label.upper()}

    return {"type": "N/A", "vector": "", "score": "N/A", "label": "UNKNOWN"}


# ──────────────────────────────────────────────
# Output (plain text for now)
# ──────────────────────────────────────────────

def print_report(findings: list[dict], packages: list[dict]) -> None:
    total_pkgs = len(packages)
    total_vulns = len(findings)

    print("\n" + "═" * 60)
    print("  pyaudit — Vulnerability Report")
    print("═" * 60)
    print(f"  Packages scanned : {total_pkgs}")
    print(f"  Vulnerabilities  : {total_vulns}")
    print("═" * 60)

    if not findings:
        print("\n  ✓ No known vulnerabilities found.\n")
        return

    for f in findings:
        aliases = ", ".join(f["aliases"]) if f["aliases"] else "—"
        fixed = ", ".join(f.get("fixed_versions", [])) if f.get("fixed_versions") else "unknown"
        print(f"\n  Package   : {f['package']} {f['version']}")
        print(f"  Vuln ID   : {f['vuln_id']}")
        print(f"  Aliases   : {aliases}")
        sev = f["severity"]
        if isinstance(sev, dict):
            label = sev.get("label", "UNKNOWN")
            score = sev.get("score", "?")
            sev_type = sev.get("type", "")
            score_str = f"{score} ({label})" if score not in ("N/A", "?") else label
            print(f"  Severity  : {score_str}  [{sev_type}]")
        else:
            print(f"  Severity  : {sev}")
        print(f"  Fix in    : {fixed}")
        print(f"  Summary   : {f['summary']}")
        print("  " + "─" * 56)

    print()


def print_json_report(findings: list[dict]) -> None:
    print(json.dumps(findings, indent=2))


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyaudit",
        description="Audit Python dependencies for known vulnerabilities via OSV.",
    )
    parser.add_argument(
        "file",
        help="Path to requirements.txt or pyproject.toml",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if any vulnerabilities are found (useful in CI)",
    )
    parser.add_argument(
        "--group",
        action="append",
        dest="groups",
        metavar="GROUP",
        help=(
            "Only audit packages in this Poetry group (e.g. --group main --group dev). "
            "Defaults to 'main' only. Can be repeated."
        ),
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help=(
            "Only audit direct dependencies declared in pyproject.toml, "
            "not transitive deps. Requires a pyproject.toml alongside the lockfile."
        ),
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # 1. Parse the dependency file
    packages = detect_and_parse(args.file, groups=args.groups, direct_only=args.direct_only)
    if not packages:
        print("No packages with pinned versions found. Nothing to audit.")
        sys.exit(0)

    print(f"Found {len(packages)} package(s) to audit.")

    # 2. Query OSV in a single batch request
    results = query_osv_batch(packages)

    # 3. Process results
    findings = process_results(packages, results)

    # 4. Report
    if args.json:
        print_json_report(findings)
    else:
        print_report(findings, packages)

    # 5. Optional non-zero exit code for CI pipelines
    if args.exit_code and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
