# 📋 correctover-compliance-check

**MCP OAuth 2.1 & CCS v1.0 Compliance Checker.**

[![PyPI version](https://img.shields.io/pypi/v/correctover-compliance-check.svg)](https://pypi.org/project/correctover-compliance-check/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

## Quick Start

```bash
pip install correctover-compliance-check
correctover-compliance-check check-full
```

## What It Does

Enforce the **2026-07-28 OAuth 2.1 mandate** for MCP servers. Verify:

- **OAuth 2.1 compliance** (8 checks) — PKCE, redirect URI, token scope
- **CCS v1.0 standard compliance** (5 checks) — Correctover Conformance Standard
- **MCP protocol compliance** (5 checks) — handshake, tool schema, error handling

### CCS v1.0 Standard

The first formal conformance standard for agentic runtimes.

DOI: [10.5281/zenodo.21234580](https://doi.org/10.5281/zenodo.21234580)

## Free Tier

50 checks/day — no credit card required.

Certification: $2,999 + $999/year — [correctover.com/checkout](https://correctover.com/checkout)

```bash
export CORRECTOVER_LICENSE_KEY=your-key-here
```

## Related Correctover Tools

| Tool | Install | Description |
|------|---------|-------------|
| **Security Scanner** | `npx correctover-scan` | MCP config security audit (14 checks) |
| **Self-Healing Test** | `pip install correctover-test` | Agent self-healing test suite |
| **Vulnerability Scan** | `pip install correctover-security-audit` | 215 fault type scanner |
| **Compliance Check** | `pip install correctover-compliance-check` | OAuth 2.1 + CCS v1.0 |
| **Runtime Guard** | `pip install correctover-runtime-guard` | 22µs RCE/SSRF interception |
| **MCP Server** | `npm install correctover-mcp-server` | 6-dimension validation |

**Website**: [correctover.com](https://correctover.com) · **GitHub**: [github.com/Correctover](https://github.com/Correctover)
