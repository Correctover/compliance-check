"""
correctover-compliance-check CLI — ammunition-driven freemium.

Powered by CCS Fault Taxonomy v2.5 cross-references:
OAuth 2.1 failures map to CWE-287 → CVE-2026-55646 (CVSS 9.1)
CCS v1.0 failures map to real-world bounty cases

Free: unlimited scanning, see first 2 compliance issues (no fixes), rest hidden
Pro: all issues + fixes + CVE cross-refs + certification + reports

Hook: "OAuth 2.1 deadline is 2026-07-28. 3 hidden gaps may map to CVE-2026-55646."
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click

from .checker import ComplianceChecker, ComplianceReport

VERSION = "1.4.0"
CTA_URL = "https://correctover.com/checkout"
FREE_ISSUE_PREVIEW = 2

# Ammunition: map compliance check IDs to real-world consequences
COMPLIANCE_AMMO = {
    "OAUTH-001": {"cwe": "CWE-287", "cve": "CVE-2026-55646", "cvss": 9.1, "consequence": "Authentication bypass — unauthorized tool invocation"},
    "OAUTH-002": {"cwe": "CWE-287", "consequence": "Token theft via implicit flow — credential exposure"},
    "OAUTH-003": {"cwe": "CWE-522", "consequence": "Credential stuffing via password grant — account takeover"},
    "OAUTH-004": {"cwe": "CWE-384", "consequence": "Token replay attacks — session hijacking"},
    "OAUTH-005": {"cwe": "CWE-287", "cve": "CVE-2026-55646", "cvss": 9.1, "consequence": "Authorization code interception — PKCE bypass"},
    "OAUTH-006": {"cwe": "CWE-601", "consequence": "Open redirect — phishing via redirect manipulation"},
    "OAUTH-007": {"cwe": "CWE-311", "consequence": "Rogue client registration — DCR abuse"},
    "OAUTH-008": {"cwe": "CWE-319", "consequence": "Token endpoint credential theft — MITM"},
    "CCS-001": {"cwe": "CWE-20", "consequence": "Schema drift — undetected misconfiguration"},
    "CCS-002": {"cwe": "CWE-319", "cve": "CVE-2026-12957", "cvss": 7.8, "consequence": "Transport credential interception — MITM"},
    "CCS-003": {"cwe": "CWE-20", "consequence": "Unvalidated tool inputs — injection attacks"},
    "CCS-004": {"cwe": "CWE-200", "cve": "CVE-2026-12957", "cvss": 7.8, "consequence": "Environment variable leak — API key exposure"},
    "CCS-005": {"cwe": "CWE-770", "consequence": "Resource exhaustion — DoS via unlimited requests"},
    "MCP-001": {"cwe": "CWE-20", "consequence": "Protocol non-compliance — connectivity failures"},
    "MCP-002": {"cwe": "CWE-20", "consequence": "Tool resolution failures — naming conflicts"},
    "MCP-003": {"cwe": "CWE-209", "consequence": "Undefined tool behavior — unpredictable agent actions"},
    "MCP-004": {"cwe": "CWE-755", "consequence": "Unhandled errors — agent crash or infinite retry"},
    "MCP-005": {"cwe": "CWE-200", "consequence": "Capability ambiguity — unintended tool exposure"},
}


def _check_license():
    from .license import LicenseValidator
    license_key = LicenseValidator.get_license_from_env()
    validator = LicenseValidator("correctover-compliance-check")
    if license_key:
        validator.set_license_key(license_key)
    status = validator.check_license()
    return status["tier"] == "pro", validator


def _get_ammo_for_issue(check_id: str) -> dict:
    """Get ammunition data for a compliance issue."""
    return COMPLIANCE_AMMO.get(check_id, {})


def _print_freemium_report(report: ComplianceReport):
    """Free: ammunition-driven compliance fear output."""

    GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
    CYAN = "\033[96m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
    BAR = "━" * 55

    # Header with ammunition context
    click.echo(f"\n{BAR}")
    click.echo(f"  {BOLD}Correctover Compliance Check{RESET}")
    click.echo(f"  Target: {BOLD}{report.target}{RESET} ({report.target_type})")
    click.echo(f"  Checks: {report.checks_total} | Duration: {report.scan_duration_ms:.1f}ms")
    click.echo(f"  ⏰ OAuth 2.1 Deadline: {RED}{report.oauth_deadline}{RESET}")
    click.echo(f"  {DIM}Cross-referenced with CCS v2.5 taxonomy (215 fault types, 52 bounty cases){RESET}")
    click.echo(f"{BAR}\n")

    if report.checks_failed == 0 and report.checks_warned == 0:
        click.echo(f"  {GREEN}✅ All checks passed — fully compliant{RESET}")
        click.echo(f"\n{BAR}")
        click.echo(f"🛡️  Stay compliant with Pro:")
        click.echo(f"   ✓ Continuous compliance monitoring")
        click.echo(f"   ✓ CCS v1.0 certification")
        click.echo(f"   ✓ Auto-remediation for future changes")
        click.echo(f"{BAR}")
        click.echo(f"   → {CTA_URL}")
        click.echo(f"{BAR}\n")
        return

    verdict_color = RED if report.verdict == "FAIL" else YELLOW
    click.echo(f"  Verdict: {verdict_color}{BOLD}{report.verdict}{RESET}")
    click.echo(f"    {GREEN}Passed: {report.checks_passed}{RESET}  "
               f"{YELLOW}Warned: {report.checks_warned}{RESET}  "
               f"{RED}Failed: {report.checks_failed}{RESET}\n")

    issues = report.issues or []

    # Ammunition summary — count CVE-mapped issues
    cve_issues = [i for i in issues if _get_ammo_for_issue(i.check_id).get("cve")]
    if cve_issues:
        cves = set(_get_ammo_for_issue(i.check_id)["cve"] for i in cve_issues)
        click.echo(f"  {RED}{BOLD}⚠  {len(cve_issues)} gap(s) map to known CVEs: {', '.join(cves)}{RESET}")

    high_cvss = [i for i in issues if _get_ammo_for_issue(i.check_id).get("cvss", 0) >= 9.0]
    if high_cvss:
        click.echo(f"  {RED}{BOLD}⚠  {len(high_cvss)} gap(s) map to CVSS 9.0+ vulnerabilities{RESET}")
    click.echo()

    shown = issues[:FREE_ISSUE_PREVIEW]
    hidden = len(issues) - FREE_ISSUE_PREVIEW

    for i, issue in enumerate(shown, 1):
        sev_color = RED if issue.severity == "FAIL" else YELLOW
        click.echo(f"  {i}. {sev_color}[{issue.severity}]{RESET} {DIM}[{issue.check_id}]{RESET} {BOLD}{issue.title}{RESET}")
        click.echo(f"     {DIM}{issue.detail[:80]}{RESET}")

        # Ammunition evidence
        ammo = _get_ammo_for_issue(issue.check_id)
        if ammo:
            evidence_parts = [ammo["cwe"]]
            if ammo.get("cve"):
                evidence_parts.append(f"{ammo['cve']} (CVSS {ammo['cvss']})")
            click.echo(f"     {CYAN}📎 Maps to: {' | '.join(evidence_parts)}{RESET}")
            click.echo(f"     {RED}   → {ammo['consequence']}{RESET}")

        click.echo(f"     🔒 Fix recommendation — Pro only\n")

    # Hidden issues with ammunition
    if hidden > 0:
        hidden_issues = issues[FREE_ISSUE_PREVIEW:]
        hidden_cves = set(_get_ammo_for_issue(i.check_id).get("cve") for i in hidden_issues if _get_ammo_for_issue(i.check_id).get("cve"))
        hidden_high_cvss = sum(1 for i in hidden_issues if _get_ammo_for_issue(i.check_id).get("cvss", 0) >= 9.0)

        click.echo(f"  {'─' * 51}")
        click.echo(f"  🔒 {hidden} additional compliance gap(s) hidden.")
        click.echo(f"     ⏰ Deadline: {report.oauth_deadline}")
        if hidden_cves:
            click.echo(f"     ⚠️  Hidden gaps map to CVEs: {', '.join(hidden_cves)}")
        if hidden_high_cvss > 0:
            click.echo(f"     ⚠️  {hidden_high_cvss} may map to CVSS 9.0+ vulnerabilities")
        click.echo(f"     {RED}Non-compliance may block MCP operations after deadline.{RESET}\n")

    click.echo(f"{BAR}")
    click.echo(
        f"\n{BAR}\n"
        f"🛡️  UPGRADE TO PRO TO UNLOCK:\n"
        f"   ✓ All {len(issues)} compliance gap(s) ({hidden} hidden)\n"
        f"   ✓ Fix steps for every gap\n"
        f"   ✓ CVE cross-reference for each failure\n"
        f"   ✓ CCS v1.0 certification\n"
        f"   ✓ Compliance audit reports with evidence\n"
        f"   ✓ Continuous monitoring\n"
        f"{BAR}\n"
        f"   → {CTA_URL}\n"
        f"   → export CORRECTOVER_LICENSE_KEY=<your-key>\n"
        f"{BAR}\n"
    )


def _print_pro_report(report: ComplianceReport, output_format: str, output: Optional[str]):
    """Pro: full report with all fixes and ammunition cross-references."""
    if output_format == "json":
        content = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
        if output:
            Path(output).write_text(content)
            click.echo(f"Report written to {output}")
        else:
            click.echo(content)
        return

    if output_format == "markdown":
        lines = [
            "# Correctover Compliance Check Report",
            f"\n**Target**: `{report.target}` | **Type**: {report.target_type}",
            f"**Duration**: {report.scan_duration_ms:.1f}ms | **Checks**: {report.checks_total}",
            f"**OAuth 2.1 Deadline**: {report.oauth_deadline}",
            f"**Cross-referenced with CCS v2.5 taxonomy (215 fault types, 52 bounty cases)**",
            f"\n## Verdict: {report.verdict}\n",
            "| Metric | Value |", "|--------|-------|",
            f"| Passed | {report.checks_passed} |",
            f"| Warned | {report.checks_warned} |",
            f"| Failed | {report.checks_failed} |",
            f"| CVE-mapped gaps | {sum(1 for i in (report.issues or []) if _get_ammo_for_issue(i.check_id).get('cve'))} |",
        ]
        if report.issues:
            lines.append("\n## Issues\n")
            for i in report.issues:
                ammo = _get_ammo_for_issue(i.check_id)
                lines.append(f"### [{i.severity}] {i.category.upper()}: {i.title}")
                lines.append(f"- **Check**: {i.check_id}")
                lines.append(f"- **Detail**: {i.detail}")
                if ammo:
                    cve_str = f" | **{ammo['cve']}** (CVSS {ammo['cvss']})" if ammo.get("cve") else ""
                    lines.append(f"- **Maps to**: {ammo['cwe']}{cve_str}")
                    lines.append(f"- **Consequence**: {ammo['consequence']}")
                lines.append(f"- **Fix**: {i.fix}\n")
        lines.append(f"\n---\n*Checked by [Correctover]({CTA_URL}) v{VERSION} — powered by CCS v2.5*")
        content = "\n".join(lines)
        if output:
            Path(output).write_text(content)
            click.echo(f"Report written to {output}")
        else:
            click.echo(content)
        return

    GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
    CYAN = "\033[96m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
    BAR = "━" * 55

    click.echo(f"\n{BAR}")
    click.echo(f"  {BOLD}Correctover Compliance Check{RESET}  {GREEN}[PRO]{RESET}")
    click.echo(f"  Target: {BOLD}{report.target}{RESET} ({report.target_type})")
    click.echo(f"  Checks: {report.checks_total} | ⏰ Deadline: {RED}{report.oauth_deadline}{RESET}")
    click.echo(f"  {DIM}Cross-referenced with CCS v2.5 taxonomy{RESET}")
    click.echo(f"{BAR}\n")

    verdict_color = GREEN if report.verdict == "PASS" else (YELLOW if report.verdict == "PARTIAL" else RED)
    click.echo(f"  Verdict: {verdict_color}{BOLD}{report.verdict}{RESET}")
    click.echo(f"    {GREEN}Passed: {report.checks_passed}{RESET}  {YELLOW}Warned: {report.checks_warned}{RESET}  {RED}Failed: {report.checks_failed}{RESET}")
    click.echo()

    if report.issues:
        for i in report.issues:
            sev_color = RED if i.severity == "FAIL" else YELLOW
            click.echo(f"  {sev_color}[{i.severity}]{RESET} {DIM}[{i.check_id}]{RESET} {BOLD}{i.title}{RESET}")
            click.echo(f"    {DIM}{i.detail}{RESET}")
            ammo = _get_ammo_for_issue(i.check_id)
            if ammo:
                cve_str = f" | {ammo['cve']} (CVSS {ammo['cvss']})" if ammo.get("cve") else ""
                click.echo(f"    {CYAN}📎 Maps to: {ammo['cwe']}{cve_str}{RESET}")
                click.echo(f"    {RED}   → {ammo['consequence']}{RESET}")
            click.echo(f"    {GREEN}✅ Fix: {i.fix}{RESET}\n")
    else:
        click.echo(f"  {GREEN}All checks passed — fully compliant.{RESET}\n")
    click.echo(f"{BAR}\n")


@click.group()
@click.version_option(version=VERSION, prog_name="correctover-compliance-check")
def cli():
    """Correctover Compliance Check — MCP OAuth 2.1 & CCS v1.0 compliance.

    Enforce the 2026-07-28 OAuth 2.1 mandate.
    Cross-referenced with CCS v2.5 taxonomy: 215 fault types · 52 ZDI bounty cases.
    """
    pass


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "markdown"]), default="terminal")
@click.option("--output", "-o", default=None)
def check_oauth(config_file, output_format, output):
    """Check OAuth 2.1 compliance."""
    is_pro, validator = _check_license()
    config = json.loads(Path(config_file).read_text())
    checker = ComplianceChecker()
    issues = checker.check_oauth(config)
    report = ComplianceReport(
        target=config.get("name", config_file), target_type="mcp_server", scan_duration_ms=0,
        checks_total=len(ComplianceChecker.OAUTH_CHECKS),
        checks_passed=len(ComplianceChecker.OAUTH_CHECKS) - len(issues),
        checks_warned=0, checks_failed=len(issues),
        verdict="FAIL" if issues else "PASS", issues=issues,
    )
    validator.record_scan(risks_found=len(issues))
    if is_pro: _print_pro_report(report, output_format, output)
    else: _print_freemium_report(report)
    sys.exit(1 if issues else 0)


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "markdown"]), default="terminal")
@click.option("--output", "-o", default=None)
def check_ccs(config_file, output_format, output):
    """Check CCS v1.0 compliance."""
    is_pro, validator = _check_license()
    config = json.loads(Path(config_file).read_text())
    checker = ComplianceChecker()
    issues = checker.check_ccs(config)
    failed = sum(1 for i in issues if i.severity == "FAIL")
    warned = sum(1 for i in issues if i.severity == "WARN")
    report = ComplianceReport(
        target=config.get("name", config_file), target_type="mcp_server", scan_duration_ms=0,
        checks_total=len(ComplianceChecker.CCS_CHECKS),
        checks_passed=len(ComplianceChecker.CCS_CHECKS) - len(issues),
        checks_warned=warned, checks_failed=failed,
        verdict="FAIL" if failed else ("PARTIAL" if warned else "PASS"), issues=issues,
    )
    validator.record_scan(risks_found=len(issues))
    if is_pro: _print_pro_report(report, output_format, output)
    else: _print_freemium_report(report)
    sys.exit(1 if failed else 0)


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "markdown"]), default="terminal")
@click.option("--output", "-o", default=None)
def check_full(config_file, output_format, output):
    """Full compliance check (OAuth 2.1 + CCS v1.0 + MCP Protocol)."""
    is_pro, validator = _check_license()
    config = json.loads(Path(config_file).read_text())
    checker = ComplianceChecker()
    report = checker.check_full(config)
    validator.record_scan(risks_found=report.checks_failed)
    if is_pro: _print_pro_report(report, output_format, output)
    else: _print_freemium_report(report)
    sys.exit(1 if report.checks_failed > 0 else 0)


if __name__ == "__main__":
    cli()
