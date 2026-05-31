"""Pretty (rich) output for --pretty flag."""

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

_SEVERITY_COLORS = {
    "CRITICAL": ("bright_white", "dark_red"),
    "HIGH":     ("bright_white", "dark_goldenrod"),
    "MEDIUM":   ("bright_white", "dark_green"),
    "LOW":      ("bright_white", "grey35"),
    "NONE":     ("white",        "grey23"),
    "UNKNOWN":  ("white",        "grey23"),
}

_console = Console()


def _severity_badge(label: str) -> Text:
    fg, bg = _SEVERITY_COLORS.get(label.upper(), ("white", "grey23"))
    return Text(f" {label.upper()} ", style=f"bold {fg} on {bg}")


def _score_str(sev: dict) -> str:
    score = sev.get("score", "?")
    if score in ("N/A", "?", None):
        return "?"
    return str(score)


def print_pretty_report(findings: list[dict], packages: list[dict], filter_threshold: str | None = None) -> None:
    from pyau.severity import meets_threshold

    _console.print()
    _console.print(f"  [bold]pyvulscan[/bold] · scanned [cyan]{len(packages)}[/cyan] packages", highlight=False)
    _console.print()

    if not findings:
        _console.print("  [bold green]✓ No known vulnerabilities found.[/bold green]")
        _console.print()
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=False,
    )
    table.add_column("package",   style="bold", no_wrap=True)
    table.add_column("installed", justify="right", style="dim")
    table.add_column("fix",       justify="right", style="green")
    table.add_column("cvss",      justify="right")
    table.add_column("severity",  justify="center")

    for f in findings:
        sev = f.get("severity", {})
        label = sev.get("label", "UNKNOWN").upper()
        score = _score_str(sev)
        fixed = f.get("fixed_versions", [])
        fix_str = fixed[0] if fixed else "—"

        table.add_row(
            Text(f["package"], style="bold"),
            f["version"],
            fix_str,
            score,
            _severity_badge(label),
        )

    _console.print(table)

    counts: dict[str, int] = {}
    for f in findings:
        lbl = f.get("severity", {}).get("label", "UNKNOWN").upper()
        counts[lbl] = counts.get(lbl, 0) + 1

    parts = [f"[bold]{len(findings)} vulnerabilities found[/bold]"]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if level in counts:
            _, bg = _SEVERITY_COLORS[level]
            parts.append(f"[{bg}]{counts[level]} {level.lower()}[/{bg}]")

    _console.print("  " + " · ".join(parts), highlight=False)
    _console.print()

    if filter_threshold:
        matched = [f for f in findings if meets_threshold(f, filter_threshold)]
        _console.print(f"  [bold]Filter:[/bold] {filter_threshold.upper()} and above · {len(matched)} finding(s)")
        _console.print()
        if matched:
            _print_pretty_details(matched)


def print_pretty_apply_fix_report(apply_results: list[dict]) -> None:
    if not apply_results:
        _console.print("\n  No changes to apply.")
        return

    result = apply_results[0]
    if "error" in result:
        _console.print(f"\n  [bold red]✗[/bold red] {result['error']}")
        return

    manifest = result.get("manifest", "?")
    lock_hint = result.get("lock_hint")
    changes = result.get("changes", [])
    applied = [c for c in changes if c.get("applied")]
    skipped = [c for c in changes if not c.get("applied")]

    _console.print()
    parts = []
    if applied:
        parts.append(f"[bold green]applied {len(applied)} fix{'es' if len(applied) != 1 else ''}[/bold green]")
    if skipped:
        parts.append(f"[yellow]{len(skipped)} skipped[/yellow]")
    if lock_hint:
        parts.append(f"run [bold cyan]`{lock_hint}`[/bold cyan] to update lockfile")

    _console.print("  [bold green]✓[/bold green] " + " · ".join(parts), highlight=False)

    if skipped:
        for c in skipped:
            reason = c.get("reason", "unknown")
            ver = c.get("new_version") or "—"
            _console.print(f"  [yellow]⚠[/yellow]  [dim]{c['package']}[/dim]  fix={ver}  ({reason})")

    _console.print()


def _print_pretty_details(findings: list[dict]) -> None:
    for f in findings:
        sev = f.get("severity", {})
        label = sev.get("label", "UNKNOWN").upper()
        _, bg = _SEVERITY_COLORS.get(label, ("white", "grey23"))
        aliases = ", ".join(f["aliases"]) if f.get("aliases") else "—"
        fixed = ", ".join(f.get("fixed_versions", [])) or "unknown"

        _console.print(f"  [bold]{f['package']}[/bold] {f['version']}  {_severity_badge(label)}")
        _console.print(f"  [dim]{f['vuln_id']}[/dim]  aliases: {aliases}")
        _console.print(f"  fix: [green]{fixed}[/green]  ·  {f.get('summary', '')}")
        _console.print()
