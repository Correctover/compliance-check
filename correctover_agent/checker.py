"""
Compliance Check Engine — OAuth 2.1, CCS v1.0, MCP Protocol compliance.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ComplianceIssue:
    check_id: str
    category: str  # oauth | ccs | mcp
    severity: str  # FAIL | WARN | INFO
    title: str
    detail: str
    fix: str


@dataclass
class ComplianceReport:
    target: str
    target_type: str
    scan_duration_ms: float
    checks_total: int
    checks_passed: int
    checks_warned: int
    checks_failed: int
    verdict: str  # PASS | PARTIAL | FAIL
    issues: list = field(default_factory=list)
    oauth_deadline: str = "2026-07-28"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "scan_duration_ms": self.scan_duration_ms,
            "checks_total": self.checks_total,
            "checks_passed": self.checks_passed,
            "checks_warned": self.checks_warned,
            "checks_failed": self.checks_failed,
            "verdict": self.verdict,
            "issues": [
                {
                    "check_id": i.check_id,
                    "category": i.category,
                    "severity": i.severity,
                    "title": i.title,
                    "detail": i.detail,
                    "fix": i.fix,
                }
                for i in self.issues
            ],
        }


class ComplianceChecker:
    """Compliance check engine leveraging CCS v1.0 validator concepts."""

    OAUTH_CHECKS = {
        "OAUTH-001": {
            "title": "Authorization Code Grant with PKCE required",
            "check": lambda cfg: _check_grant_type(cfg, "authorization_code"),
            "detail_fail": "Missing or unsupported authorization_code grant with PKCE.",
            "fix": "Implement RFC 7636 PKCE with S256 code challenge on authorization_code flow.",
        },
        "OAUTH-002": {
            "title": "No Implicit Grant",
            "check": lambda cfg: _check_no_implicit(cfg),
            "detail_fail": "Implicit grant detected — removed in OAuth 2.1.",
            "fix": "Migrate from implicit to authorization_code + PKCE.",
        },
        "OAUTH-003": {
            "title": "No Resource Owner Password Grant",
            "check": lambda cfg: _check_no_password_grant(cfg),
            "detail_fail": "Resource Owner Password grant detected — removed in OAuth 2.1.",
            "fix": "Replace password grant with authorization_code + PKCE.",
        },
        "OAUTH-004": {
            "title": "Refresh Token Rotation",
            "check": lambda cfg: _check_refresh_rotation(cfg),
            "detail_fail": "Refresh tokens not configured for rotation or sender-constraining.",
            "fix": "Enable refresh token rotation with reuse detection per OAuth 2.1 §6.",
        },
        "OAUTH-005": {
            "title": "PKCE Required (even for confidential clients)",
            "check": lambda cfg: _check_pkce_required(cfg),
            "detail_fail": "PKCE not enforced — OAuth 2.1 mandates PKCE for all clients.",
            "fix": "Enforce PKCE (S256) on all authorization code exchanges.",
        },
        "OAUTH-006": {
            "title": "Redirect URI Exact Matching",
            "check": lambda cfg: _check_redirect_uri(cfg),
            "detail_fail": "Redirect URI validation is permissive or missing.",
            "fix": "Use exact redirect URI matching per OAuth 2.1 §4.1.",
        },
        "OAUTH-007": {
            "title": "DCR Metadata Compliance",
            "check": lambda cfg: _check_dcr_metadata(cfg),
            "detail_fail": "Dynamic Client Registration metadata missing required fields.",
            "fix": "Include client_name, redirect_uris, grant_types, and token_endpoint_auth_method in DCR metadata per RFC 7591.",
        },
        "OAUTH-008": {
            "title": "Token Endpoint Auth Method",
            "check": lambda cfg: _check_token_auth_method(cfg),
            "detail_fail": "Token endpoint auth method is insecure (client_secret_post with no TLS verification).",
            "fix": "Use private_key_jwt or mutual TLS for token endpoint authentication.",
        },
    }

    CCS_CHECKS = {
        "CCS-001": {
            "title": "CCS v1.0 Schema Compliance",
            "check": lambda cfg: _check_ccs_schema(cfg),
            "detail_fail": "MCP Server config does not conform to CCS v1.0 schema.",
            "fix": "Validate against CCS v1.0 JSON Schema: https://correctover.com/ccs/v1/schema.json",
        },
        "CCS-002": {
            "title": "Transport Security — HTTPS Only",
            "check": lambda cfg: _check_https_transport(cfg),
            "detail_fail": "Non-HTTPS transport detected for remote MCP server.",
            "fix": "Enforce TLS 1.3+ for all remote transport connections.",
        },
        "CCS-003": {
            "title": "Tool Schema Validation Required",
            "check": lambda cfg: _check_tool_schema_validation(cfg),
            "detail_fail": "MCP tool definitions missing input/output JSON Schema.",
            "fix": "Add inputSchema and outputSchema to all tool definitions per MCP spec.",
        },
        "CCS-004": {
            "title": "Environment Variable Scoping",
            "check": lambda cfg: _check_env_scoping(cfg),
            "detail_fail": "Environment variables exposed without scope restrictions.",
            "fix": "Scope env vars using allowlist/prefix filtering per CCS v1.0 §7.3.",
        },
        "CCS-005": {
            "title": "Rate Limiting Configuration",
            "check": lambda cfg: _check_rate_limiting(cfg),
            "detail_fail": "No rate limiting configured for MCP server endpoints.",
            "fix": "Add rate limiting: 100 req/min per tool, 1000 req/min per server.",
        },
    }

    MCP_CHECKS = {
        "MCP-001": {
            "title": "MCP Transport Compliance",
            "check": lambda cfg: _check_transport_type(cfg),
            "detail_fail": "Transport type not specified or unsupported (must be stdio, sse, or streamable-http).",
            "fix": "Set transport to 'streamable-http' (recommended) or 'sse' per MCP spec 2025-11-25.",
        },
        "MCP-002": {
            "title": "Tool Naming Convention",
            "check": lambda cfg: _check_tool_naming(cfg),
            "detail_fail": "Tool names do not follow snake_case convention per MCP spec.",
            "fix": "Rename tools to snake_case (e.g., 'search_docs' not 'searchDocs').",
        },
        "MCP-003": {
            "title": "Tool Description Completeness",
            "check": lambda cfg: _check_tool_descriptions(cfg),
            "detail_fail": "One or more tools missing description field.",
            "fix": "Every tool must have a non-empty 'description' field.",
        },
        "MCP-004": {
            "title": "Error Response Standard",
            "check": lambda cfg: _check_error_format(cfg),
            "detail_fail": "Error handling does not follow MCP error response standard.",
            "fix": "Return errors as MCP-standard JSON-RPC error objects with code, message, and optional data.",
        },
        "MCP-005": {
            "title": "Server Capability Declaration",
            "check": lambda cfg: _check_capabilities(cfg),
            "detail_fail": "Missing or incomplete server capabilities declaration.",
            "fix": "Declare supported capabilities: tools, resources, prompts, logging per MCP initialize response.",
        },
    }

    def __init__(self):
        self.issues: list[ComplianceIssue] = []

    def check_oauth(self, config: dict) -> list[ComplianceIssue]:
        issues = []
        auth_config = config.get("auth", config.get("oauth", {}))
        for check_id, spec in self.OAUTH_CHECKS.items():
            passed, detail = spec["check"](auth_config)
            if not passed:
                issues.append(
                    ComplianceIssue(
                        check_id=check_id,
                        category="oauth",
                        severity="FAIL",
                        title=spec["title"],
                        detail=detail or spec["detail_fail"],
                        fix=spec["fix"],
                    )
                )
        return issues

    def check_ccs(self, config: dict) -> list[ComplianceIssue]:
        issues = []
        for check_id, spec in self.CCS_CHECKS.items():
            passed, detail = spec["check"](config)
            if not passed:
                severity = "WARN" if check_id in ("CCS-004", "CCS-005") else "FAIL"
                issues.append(
                    ComplianceIssue(
                        check_id=check_id,
                        category="ccs",
                        severity=severity,
                        title=spec["title"],
                        detail=detail or spec["detail_fail"],
                        fix=spec["fix"],
                    )
                )
        return issues

    def check_mcp(self, config: dict) -> list[ComplianceIssue]:
        issues = []
        for check_id, spec in self.MCP_CHECKS.items():
            passed, detail = spec["check"](config)
            if not passed:
                severity = "WARN" if check_id in ("MCP-004",) else "FAIL"
                issues.append(
                    ComplianceIssue(
                        check_id=check_id,
                        category="mcp",
                        severity=severity,
                        title=spec["title"],
                        detail=detail or spec["detail_fail"],
                        fix=spec["fix"],
                    )
                )
        return issues

    def check_full(self, config: dict) -> ComplianceReport:
        start = time.time()
        self.issues = []

        self.issues.extend(self.check_oauth(config))
        self.issues.extend(self.check_ccs(config))
        self.issues.extend(self.check_mcp(config))

        total = len(self.OAUTH_CHECKS) + len(self.CCS_CHECKS) + len(self.MCP_CHECKS)
        failed = sum(1 for i in self.issues if i.severity == "FAIL")
        warned = sum(1 for i in self.issues if i.severity == "WARN")
        passed = total - failed - warned

        if failed == 0 and warned == 0:
            verdict = "PASS"
        elif failed == 0:
            verdict = "PARTIAL"
        else:
            verdict = "FAIL"

        return ComplianceReport(
            target=config.get("name", "unknown"),
            target_type="mcp_server",
            scan_duration_ms=(time.time() - start) * 1000,
            checks_total=total,
            checks_passed=passed,
            checks_warned=warned,
            checks_failed=failed,
            verdict=verdict,
            issues=self.issues,
        )


# --- OAuth 2.1 check helpers ---

def _check_grant_type(cfg: dict, expected: str) -> tuple[bool, str]:
    grants = cfg.get("grant_types", cfg.get("grants", []))
    if not isinstance(grants, list):
        grants = [grants]
    if expected not in grants:
        return False, f"Grant type '{expected}' not found in {grants}"
    if "pkce" not in str(cfg).lower() and "code_challenge" not in str(cfg).lower():
        return False, "PKCE not detected alongside authorization_code"
    return True, ""


def _check_no_implicit(cfg: dict) -> tuple[bool, str]:
    grants = cfg.get("grant_types", cfg.get("grants", []))
    if not isinstance(grants, list):
        grants = [grants]
    if "implicit" in [g.lower() for g in grants]:
        return False, "Implicit grant found in grant_types"
    return True, ""


def _check_no_password_grant(cfg: dict) -> tuple[bool, str]:
    grants = cfg.get("grant_types", cfg.get("grants", []))
    if not isinstance(grants, list):
        grants = [grants]
    if any(g.lower() in ("password", "resource_owner", "ropc") for g in grants):
        return False, "Password grant found in grant_types"
    return True, ""


def _check_refresh_rotation(cfg: dict) -> tuple[bool, str]:
    if cfg.get("refresh_token_rotation") or cfg.get("rotation_enabled"):
        return True, ""
    return False, ""


def _check_pkce_required(cfg: dict) -> tuple[bool, str]:
    pkce_method = cfg.get("pkce_method", cfg.get("code_challenge_method", ""))
    if pkce_method.upper() not in ("S256",):
        return False, f"PKCE method is '{pkce_method}', expected 'S256'"
    return True, ""


def _check_redirect_uri(cfg: dict) -> tuple[bool, str]:
    uris = cfg.get("redirect_uris", cfg.get("redirect_uri", []))
    if not uris:
        return True, ""
    for uri in uris:
        if "*" in str(uri) or "wildcard" in str(uri).lower():
            return False, f"Wildcard redirect URI detected: {uri}"
    return True, ""


def _check_dcr_metadata(cfg: dict) -> tuple[bool, str]:
    required = ["client_name", "redirect_uris", "grant_types"]
    missing = [f for f in required if not cfg.get(f)]
    if missing:
        return False, f"Missing DCR metadata fields: {', '.join(missing)}"
    return True, ""


def _check_token_auth_method(cfg: dict) -> tuple[bool, str]:
    method = cfg.get("token_endpoint_auth_method", cfg.get("auth_method", ""))
    if method in ("client_secret_basic", "client_secret_post", ""):
        return False, f"Auth method '{method or 'not set'}' is insecure for production"
    return True, ""


# --- CCS v1.0 check helpers ---

def _check_ccs_schema(cfg: dict) -> tuple[bool, str]:
    if cfg.get("ccs_version") or cfg.get("correctover") or cfg.get("compliance"):
        return True, ""
    return False, ""


def _check_https_transport(cfg: dict) -> tuple[bool, str]:
    url = cfg.get("url", cfg.get("endpoint", ""))
    if not url:
        return True, ""
    if not url.startswith("https://"):
        return False, f"Transport URL uses '{url.split('://')[0]}' instead of HTTPS"
    return True, ""


def _check_tool_schema_validation(cfg: dict) -> tuple[bool, str]:
    tools = cfg.get("tools", [])
    if not tools:
        return True, ""
    missing_schema = []
    for t in tools:
        if not t.get("inputSchema") and not t.get("input_schema"):
            missing_schema.append(t.get("name", "unnamed"))
    if missing_schema:
        return False, f"Tools missing input schema: {', '.join(missing_schema)}"
    return True, ""


def _check_env_scoping(cfg: dict) -> tuple[bool, str]:
    env_vars = cfg.get("env", cfg.get("environment", {}))
    if not env_vars:
        return True, ""
    if not cfg.get("env_scoping") and not cfg.get("env_allowlist"):
        return False, ""
    return True, ""


def _check_rate_limiting(cfg: dict) -> tuple[bool, str]:
    rl = cfg.get("rate_limiting", cfg.get("rate_limit", {}))
    if not rl:
        return False, ""
    return True, ""


# --- MCP Protocol check helpers ---

def _check_transport_type(cfg: dict) -> tuple[bool, str]:
    transport = cfg.get("transport", cfg.get("protocol", ""))
    valid = ("stdio", "sse", "streamable-http", "streamable_http")
    if transport.lower() not in valid:
        return False, f"Transport '{transport}' not valid. Must be one of {valid}"
    return True, ""


def _check_tool_naming(cfg: dict) -> tuple[bool, str]:
    tools = cfg.get("tools", [])
    bad_names = []
    for t in tools:
        name = t.get("name", "")
        if name and not name.islower() and "_" not in name:
            if any(c.isupper() for c in name):
                bad_names.append(name)
    if bad_names:
        return False, f"Non-snake_case tool names: {', '.join(bad_names)}"
    return True, ""


def _check_tool_descriptions(cfg: dict) -> tuple[bool, str]:
    tools = cfg.get("tools", [])
    missing = []
    for t in tools:
        desc = t.get("description", "")
        if not desc or not desc.strip():
            missing.append(t.get("name", "unnamed"))
    if missing:
        return False, f"Tools missing description: {', '.join(missing)}"
    return True, ""


def _check_error_format(cfg: dict) -> tuple[bool, str]:
    if not cfg.get("error_handler") and not cfg.get("error_format"):
        return False, ""
    return True, ""


def _check_capabilities(cfg: dict) -> tuple[bool, str]:
    caps = cfg.get("capabilities", cfg.get("server_capabilities", {}))
    if not caps:
        return False, ""
    return True, ""
