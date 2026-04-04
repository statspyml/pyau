import argparse
import sys

from pyau.osv.client import query_osv_batch
from pyau.osv.processor import process_results
from pyau.parsers import detect_and_parse
from pyau.report import print_json_report, print_multiscan_json_report, print_multiscan_report, print_report

_SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyau",
        description="Audit Python dependencies for known vulnerabilities via OSV.",
    )
    parser.add_argument(
        "file",
        help="Path to uv.lock, poetry.lock, pyproject.toml, or requirements.txt",
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
    parser.add_argument(
        "--filter",
        dest="filter_threshold",
        metavar="LEVEL",
        choices=_SEVERITY_LEVELS,
        help=(
            "Add a summary section at the end of the report showing only findings "
            "at or above this severity level (LOW, MEDIUM, HIGH, CRITICAL). "
            "The full report is always shown."
        ),
    )
    return parser


def build_multiscan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyau multiscan",
        description=(
            "Scan multiple projects for vulnerabilities using a config file.\n\n"
            "The config file lists directories to scan. Supported formats:\n"
            "  .json  — list or {\"projects\": [...]}\n"
            "  .yaml  — list or projects: [...]\n"
            "  .py    — defines a top-level 'projects' list"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "config",
        help="Path to config file (.json, .yaml/.yml, or .py)",
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
        "--filter",
        dest="filter_threshold",
        metavar="LEVEL",
        choices=_SEVERITY_LEVELS,
        help=(
            "Add a summary section at the end of the report showing only findings "
            "at or above this severity level (LOW, MEDIUM, HIGH, CRITICAL). "
            "The full report is always shown."
        ),
    )
    return parser


def main() -> None:
    # Dispatch 'multiscan' subcommand before the normal parser so that the
    # existing positional 'file' argument keeps working unchanged.
    if len(sys.argv) > 1 and sys.argv[1] == "multiscan":
        _run_multiscan(sys.argv[2:])
        return

    parser = build_parser()
    args = parser.parse_args()

    # 1. Parse the dependency file
    packages = detect_and_parse(
        args.file,
        groups=args.groups,
        direct_only=args.direct_only,
    )
    if not packages:
        print("No packages with pinned versions found. Nothing to audit.")
        sys.exit(0)

    print(f"Found {len(packages)} package(s) to audit.")

    # 2. Batch query OSV
    results = query_osv_batch(packages)

    # 3. Fetch full details and process
    findings = process_results(packages, results)

    # 4. Report
    if args.json:
        print_json_report(findings)
    else:
        print_report(findings, packages, filter_threshold=args.filter_threshold)

    # 5. CI-friendly exit code
    if args.exit_code and findings:
        sys.exit(1)


def _run_multiscan(argv: list[str]) -> None:
    from pyau.multiscan import load_config, run_multiscan

    parser = build_multiscan_parser()
    args = parser.parse_args(argv)

    projects = load_config(args.config)
    if not projects:
        print("No projects listed in config. Nothing to scan.")
        sys.exit(0)

    print(f"Multiscan: {len(projects)} project(s) configured.")
    scan_results = run_multiscan(projects)

    if args.json:
        print_multiscan_json_report(scan_results)
    else:
        print_multiscan_report(scan_results, filter_threshold=args.filter_threshold)

    if args.exit_code and any(r["vulnerabilities_found"] > 0 for r in scan_results):
        sys.exit(1)


if __name__ == "__main__":
    main()
