import argparse
import sys

from pyau.osv.client import query_osv_batch
from pyau.osv.processor import process_results
from pyau.parsers import detect_and_parse
from pyau.report import print_json_report, print_report


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
    return parser


def main() -> None:
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
        print_report(findings, packages)

    # 5. CI-friendly exit code
    if args.exit_code and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
