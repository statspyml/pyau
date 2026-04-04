"""MCP server for pyvulscan using fastmcp."""

import json
import os
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from pyau.osv.client import query_osv_batch
from pyau.osv.processor import process_results
from pyau.parsers import detect_and_parse

# Initialize FastMCP server
mcp = FastMCP("pyvulscan")


@mcp.tool()
def scan_vulnerabilities(
    file_path: str,
    groups: list[str] | None = None,
    direct_only: bool = False,
) -> dict[str, Any]:
    """
    Scan a Python dependency file for known vulnerabilities.

    Supports: requirements.txt, poetry.lock, uv.lock, pyproject.toml

    Args:
        file_path: Path to the dependency file to scan
        groups: Poetry groups to audit (e.g., ["main", "dev"]). Defaults to ["main"]
        direct_only: Only audit direct dependencies (requires pyproject.toml)

    Returns:
        Dictionary with scan results including vulnerabilities found
    """
    try:
        # Resolve absolute path
        abs_path = Path(file_path).resolve()
        if not abs_path.exists():
            return {
                "success": False,
                "error": f"File not found: {file_path}",
            }

        # Parse dependencies
        packages = detect_and_parse(
            str(abs_path),
            groups=groups,
            direct_only=direct_only,
        )

        if not packages:
            return {
                "success": True,
                "packages_scanned": 0,
                "vulnerabilities_found": 0,
                "findings": [],
                "message": "No packages with pinned versions found.",
            }

        # Query OSV API
        results = query_osv_batch(packages)

        # Process results
        findings = process_results(packages, results)

        return {
            "success": True,
            "file": str(abs_path),
            "packages_scanned": len(packages),
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@mcp.tool()
def scan_directory(
    directory_path: str = ".",
    groups: list[str] | None = None,
    direct_only: bool = False,
) -> dict[str, Any]:
    """
    Scan a directory for Python dependency files and check for vulnerabilities.

    Automatically detects: requirements.txt, poetry.lock, uv.lock, pyproject.toml

    Args:
        directory_path: Path to the directory to scan (defaults to current directory)
        groups: Poetry groups to audit (e.g., ["main", "dev"]). Defaults to ["main"]
        direct_only: Only audit direct dependencies (requires pyproject.toml)

    Returns:
        Dictionary with scan results for all detected dependency files
    """
    try:
        # Resolve directory path
        dir_path = Path(directory_path).resolve()
        if not dir_path.exists():
            return {
                "success": False,
                "error": f"Directory not found: {directory_path}",
            }

        if not dir_path.is_dir():
            return {
                "success": False,
                "error": f"Path is not a directory: {directory_path}",
            }

        # Detect dependency files
        dependency_files = [
            "requirements.txt",
            "poetry.lock",
            "uv.lock",
            "pyproject.toml",
        ]

        found_files = []
        for dep_file in dependency_files:
            file_path = dir_path / dep_file
            if file_path.exists():
                found_files.append(str(file_path))

        if not found_files:
            return {
                "success": True,
                "directory": str(dir_path),
                "files_found": [],
                "message": "No dependency files found in directory.",
            }

        # Scan each file
        all_results = []
        total_vulns = 0

        for file_path in found_files:
            result = scan_vulnerabilities(file_path, groups, direct_only)
            all_results.append({
                "file": file_path,
                "result": result,
            })
            if result.get("success"):
                total_vulns += result.get("vulnerabilities_found", 0)

        return {
            "success": True,
            "directory": str(dir_path),
            "files_scanned": len(found_files),
            "total_vulnerabilities": total_vulns,
            "results": all_results,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


def _find_package_version(package_name: str, directory: str = ".") -> str | None:
    """
    Find the version of a package installed in the project.

    Searches through uv.lock, poetry.lock, pyproject.toml, and requirements.txt
    to find the version of the specified package.

    Args:
        package_name: Name of the package to find
        directory: Directory to search in (defaults to current directory)

    Returns:
        Version string if found, None otherwise
    """
    dir_path = Path(directory).resolve()

    # Check dependency files in order of preference
    dependency_files = [
        "uv.lock",
        "poetry.lock",
        "requirements.txt",
        "pyproject.toml",
    ]

    for dep_file in dependency_files:
        file_path = dir_path / dep_file
        if not file_path.exists():
            continue

        try:
            # Parse the file using existing parser
            packages = detect_and_parse(str(file_path))

            # Find the package in the parsed results
            for pkg in packages:
                if pkg["name"].lower() == package_name.lower():
                    return pkg["version"]

        except Exception:
            # If parsing fails, continue to next file
            continue

    return None


@mcp.tool()
def check_package(
    package_name: str,
    version: str | None = None,
    directory: str = ".",
) -> dict[str, Any]:
    """
    Check a specific Python package version for known vulnerabilities.

    If version is not provided, attempts to detect it from project dependency files
    (uv.lock, poetry.lock, requirements.txt, or pyproject.toml).

    Args:
        package_name: Name of the Python package (e.g., "django")
        version: Version to check (e.g., "3.2.0"). If not provided, will auto-detect from project
        directory: Directory to search for dependency files (defaults to current directory)

    Returns:
        Dictionary with vulnerability information for the package
    """
    try:
        # If version not provided, try to detect it from project files
        if version is None:
            version = _find_package_version(package_name, directory)
            if version is None:
                return {
                    "success": False,
                    "error": f"Package '{package_name}' not found in project dependency files. "
                    f"Please specify the version explicitly or ensure the package is listed in "
                    f"uv.lock, poetry.lock, requirements.txt, or pyproject.toml",
                }

        # Create a package dict
        packages = [{"name": package_name, "version": version}]

        # Query OSV API
        results = query_osv_batch(packages)

        # Process results
        findings = process_results(packages, results)

        return {
            "success": True,
            "package": package_name,
            "version": version,
            "version_source": "auto-detected from project" if version else "provided",
            "vulnerabilities_found": len(findings),
            "findings": findings,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
