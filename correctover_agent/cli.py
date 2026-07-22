"""
correctover-compliance-check CLI — MCP OAuth 2.1 & CCS v1.0 compliance checker.

Usage:
    correctover-compliance-check check-oauth <config.json>
    correctover-compliance-check check-ccs <config.json>
    correctover-compliance-check check-full <config.json>
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click

from .checker import ComplianceChecker, ComplianceReport
from .license import LicenseValidator, check_and_record, LicenseExceededError

VERSION = "1.1.0"
CTA_URL = "https://correctover.com/checkout"
PRICING_AUTH = "$2,999"
PRICING_ANNUAL = "$999"


def _print_report(report: ComplianceReport, output_format: str, output: Optional[str]):
    if output_format == "json":
        content = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
        if output:
            Path(output).write_text(content)
            click.echo(f"Report written to {output}")
        else:
            click.echo(content)

    elif output_format == "markdown":
        lines = [
            f"# Correctover Compliance Check Report",
            f"",
            f"**Target**: `{report.target}` | **Type**: {report.target_type}",
            f"**Duration**: {report.scan_duration_ms:.1f}ms | **Checks**: {report.checks_total}",
            f"**OAuth 2.1 Deadline**: {report.oauth_deadline}",
            f"",
            f"## Verdict: {report.verdict}",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Passed | {report.checks_passed} |",
            f"| Warned | {report.checks_warned} |",
            f"| Failed | {report.checks_failed} |",
            f"",
        ]
        if report.issues:
            lines.append("## Issues")
            lines.append("")
            for i in report.issues:
                lines.append(f"### [{i.severity}] {i.category.upper()}: {i.title}")
                lines.append(f"- **Check**: {i.check_id}")
                lines.append(f"- **Detail**: {i.detail}")
                lines.append(f"- **Fix**: {i.fix}")
                lines.append("")

        lines.append("---")
        lines.append(f"*Checked by [Correctover Compliance Check]({CTA_URL}) v{VERSION}*")
        lines.append(f"*Pricing: Auth Fee {PRICING_AUTH} + Annual {PRICING_ANNUAL}*")

        content = "\n".join(lines)
        if output:
            Path(output).write_text(content)
            click.echo(f"Report written to {output}")
        else:
            click.echo(content)

    else:  # terminal
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        CYAN = "\033[96m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"

        verdict_color = GREEN if report.verdict == "PASS" else (YELLOW if report.verdict == "PARTIAL" else RED)

        click.echo(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
        click.echo(f"{CYAN}{BOLD}║{RESET}   {BOLD}Correctover Compliance Check Report{RESET}       {CYAN}{BOLD}║{RESET}")
        click.echo(f"{CYAN}{BOLD}╚══════════════════════════════════════════════╝{RESET}\n")
        click.echo(f"  Target: {BOLD}{report.target}{RESET} ({report.target_type})")
        click.echo(f"  Duration: {report.scan_duration_ms:.1f}ms | Checks: {report.checks_total}")
        click.echo(f"  OAuth 2.1 Deadline: {RED}{report.oauth_deadline}{RESET}")
        click.echo()
        click.echo(f"  Verdict: {verdict_color}{BOLD}{report.verdict}{RESET}")
        click.echo(f"    {GREEN}Passed: {report.checks_passed}{RESET}  "
                   f"{YELLOW}Warned: {report.checks_warned}{RESET}  "
                   f"{RED}Failed: {report.checks_failed}{RESET}")
        click.echo()

        if report.issues:
            for i in report.issues:
                sev_color = RED if i.severity == "FAIL" else YELLOW
                click.echo(f"  {sev_color}[{i.severity}]{RESET} {DIM}[{i.check_id}]{RESET} {BOLD}{i.title}{RESET}")
                click.echo(f"    {DIM}{i.detail}{RESET}")
                click.echo(f"    {GREEN}Fix: {i.fix}{RESET}")
                click.echo()
        else:
            click.echo(f"  {GREEN}All checks passed — fully compliant.{RESET}\n")

        # CTA
        click.echo(f"{CYAN}{BOLD}┌─────────────────────────────────────────────────┐{RESET}")
        click.echo(f"{CYAN}{BOLD}│{RESET}  🛡️  Get compliant → {CTA_URL}       {CYAN}{BOLD}│{RESET}")
        click.echo(f"{CYAN}{BOLD}│{RESET}  {DIM}Auth Fee {PRICING_AUTH} + Annual {PRICING_ANNUAL}{RESET}              {CYAN}{BOLD}│{RESET}")
        click.echo(f"{CYAN}{BOLD}│{RESET}  {DIM}Deadline: {report.oauth_deadline} — OAuth 2.1 mandate{RESET}  {CYAN}{BOLD}│{RESET}")
        click.echo(f"{CYAN}{BOLD}└─────────────────────────────────────────────────┘{RESET}\n")


@click.group()
@click.version_option(version=VERSION, prog_name="correctover-compliance-check")
def cli():
    """Correctover Compliance Check — MCP OAuth 2.1 & CCS v1.0 compliance.

    Enforce the 2026-07-28 OAuth 2.1 mandate.
    Verify MCP protocol compliance (transport, auth, tool schema).
    """
    pass


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "markdown"]), default="terminal")
@click.option("--output", "-o", default=None, help="Output file path")
def check_oauth(config_file: str, output_format: str, output: Optional[str]):
    """Check OAuth 2.1 compliance only."""
    # License check
    license_key = LicenseValidator.get_license_from_env()
    validator = LicenseValidator("correctover-compliance-check")
    if license_key:
        validator.set_license_key(license_key)
    status = validator.record_call()
    tier = status.get('tier', 'free')
    remaining = status.get('calls_remaining', 0)
    if tier == 'free':
        click.echo('Free tier: {} calls remaining today ({}/{})'.format(remaining, status['calls_today'], validator.FREE_LIMIT_PER_DAY), err=True)
        click.echo('   Upgrade: https://correctover.com/checkout', err=True)
    elif tier == 'pro':
        click.echo('Pro license active - unlimited calls', err=True)
    config = json.loads(Path(config_file).read_text())
    checker = ComplianceChecker()
    issues = checker.check_oauth(config)
    report = ComplianceReport(
        target=config.get("name", config_file),
        target_type="mcp_server",
        scan_duration_ms=0,
        checks_total=len(ComplianceChecker.OAUTH_CHECKS),
        checks_passed=len(ComplianceChecker.OAUTH_CHECKS) - len(issues),
        checks_warned=0,
        checks_failed=len(issues),
        verdict="FAIL" if issues else "PASS",
        issues=issues,
    )
    _print_report(report, output_format, output)
    sys.exit(1 if issues else 0)


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "markdown"]), default="terminal")
@click.option("--output", "-o", default=None, help="Output file path")
def check_ccs(config_file: str, output_format: str, output: Optional[str]):
    """Check CCS v1.0 compliance only."""
    config = json.loads(Path(config_file).read_text())
    checker = ComplianceChecker()
    issues = checker.check_ccs(config)
    failed = sum(1 for i in issues if i.severity == "FAIL")
    warned = sum(1 for i in issues if i.severity == "WARN")
    report = ComplianceReport(
        target=config.get("name", config_file),
        target_type="mcp_server",
        scan_duration_ms=0,
        checks_total=len(ComplianceChecker.CCS_CHECKS),
        checks_passed=len(ComplianceChecker.CCS_CHECKS) - len(issues),
        checks_warned=warned,
        checks_failed=failed,
        verdict="FAIL" if failed else ("PARTIAL" if warned else "PASS"),
        issues=issues,
    )
    _print_report(report, output_format, output)
    sys.exit(1 if failed else 0)


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "markdown"]), default="terminal")
@click.option("--output", "-o", default=None, help="Output file path")
def check_full(config_file: str, output_format: str, output: Optional[str]):
    """Run full compliance check (OAuth 2.1 + CCS v1.0 + MCP Protocol)."""
    config = json.loads(Path(config_file).read_text())
    checker = ComplianceChecker()
    report = checker.check_full(config)
    _print_report(report, output_format, output)
    sys.exit(1 if report.checks_failed > 0 else 0)


if __name__ == "__main__":
    cli()
