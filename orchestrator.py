"""
orchestrator.py
The actual MCP server. Wraps the already-tested tool modules
(recon, vuln_scan, exploit, reporting) with @mcp.tool() decorators via
FastMCP, so any MCP-compatible client (Claude Desktop, LobeHub, an
Ollama MCP bridge) can drive this red-team lab instead of only the
standalone ai_controller.py.

IMPORTANT — this uses stdio transport (mcp.run()):
  Do NOT run `python3 orchestrator.py` directly in a terminal and type
  at it — it expects JSON-RPC over stdio from a real MCP client, not
  keyboard input, and will just appear to hang.

  To test standalone:      mcp dev orchestrator.py
  To use for real:         point your MCP client's config at this
                            file (see bottom of this docstring for an
                            example Claude Desktop config snippet).

TRUST MODEL — read before connecting this to a client:
  Unlike ai_controller.py, this server has NO input()-based
  confirmation gate for exploit.py's tools — stdio/JSON-RPC has no
  terminal to prompt against. Instead, every exploit-tooling function
  below is marked with a loud warning in its description string, and
  we are relying on the MCP CLIENT's own human-in-the-loop approval
  UI (e.g. Claude Desktop's per-call "Allow this tool?" prompt) as the
  confirmation gate instead. If you connect this to a client that
  auto-approves tool calls without asking you, the exploit tools lose
  their human checkpoint entirely — verify your client prompts for
  approval before relying on that.

  Every tool, exploit or not, still independently re-validates targets
  against tools/allowlist.py server-side regardless of what any client
  or model requests — that check is not something a client's UI can
  bypass.

  NOTE ON THE ALLOWLIST TEXT BELOW: the tool descriptions below spell
  out the allowlisted IPs as static text for reliability (Python
  docstrings must be plain string literals to be picked up by
  introspection — an f-string here would silently evaluate to no
  docstring at all, which was caught and fixed during development).
  If you edit tools/allowlist.py to add/remove devices, also update
  the docstrings below to match — they are NOT auto-synced.

Example Claude Desktop config (claude_desktop_config.json):
    {
      "mcpServers": {
        "redteam-mcp": {
          "command": "python3",
          "args": ["/absolute/path/to/ai-redteam/orchestrator.py"]
        }
      }
    }
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from tools import recon, vuln_scan, exploit, reporting
from tools.allowlist import NotAllowedError, InvalidInputError

mcp = FastMCP("redteam-mcp")

# Keep in sync with tools/allowlist.py manually — see note in module
# docstring above for why this isn't interpolated dynamically.
# No real IPs live in source anymore — every docstring below just points
# operators/models at config/allowlist.json instead of spelling out actual
# device addresses in tracked code.


def _safe_call(fn, **kwargs) -> dict:
    """
    Shared error boundary for every tool below. Scope/validation errors
    come back as a structured dict instead of an uncaught exception
    bubbling up as a raw MCP protocol error — keeps the failure mode
    legible to whatever client/model is driving this.
    """
    try:
        return fn(**kwargs)
    except (NotAllowedError, InvalidInputError, ValueError) as exc:
        return {"error": str(exc), "tool": fn.__name__}


# ---------------------------------------------------------------------------
# Recon tools
# ---------------------------------------------------------------------------

@mcp.tool()
def nmap_scan(target: str, ports: str = "1-1024", scan_type: str = "-sT") -> dict:
    """Run an nmap scan against an allowlisted personal-lab device.

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list. Any other target is rejected server-side
    regardless of what is requested.

    target: literal allowlisted IP.
    ports: nmap port spec, e.g. "1-1024", "22,80,443".
    scan_type: one of -sT (connect), -sS (SYN, needs root), -sU (UDP),
        -sV (version detection), -A (aggressive).
    """
    return _safe_call(recon.nmap_scan, target=target, ports=ports, scan_type=scan_type)


@mcp.tool()
def dig_lookup(target: str, record_type: str = "A") -> dict:
    """DNS lookup for an allowlisted target IP.

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list.

    record_type: one of A, AAAA, TXT, MX, NS, PTR, SOA.
    """
    return _safe_call(recon.dig_lookup, target=target, record_type=record_type)


@mcp.tool()
def whois_lookup(target: str) -> dict:
    """WHOIS lookup for an allowlisted target IP.

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list. Note: RFC1918 private addresses will typically
    return IANA reserved-space boilerplate, not useful registrant info.
    """
    return _safe_call(recon.whois_lookup, target=target)


@mcp.tool()
def banner_grab(target: str, port: int, timeout: float = 3.0) -> dict:
    """Connect to a TCP port on an allowlisted target and read whatever
    service banner it volunteers on connect (no data sent).

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list.
    """
    return _safe_call(recon.banner_grab, target=target, port=port, timeout=timeout)


@mcp.tool()
def http_headers(target: str, port: int = 80, use_tls: bool = False, path: str = "/") -> dict:
    """Fetch HTTP response headers from an allowlisted target via curl -I.

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list.
    """
    return _safe_call(recon.http_headers, target=target, port=port, use_tls=use_tls, path=path)


# ---------------------------------------------------------------------------
# Vuln scan tools
# ---------------------------------------------------------------------------

@mcp.tool()
def nikto_scan(target: str, port: int = 80, use_tls: bool = False) -> dict:
    """Run nikto web-vuln scan against an allowlisted target's web service.
    Slow by design (large known-issue checklist).

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list.
    """
    return _safe_call(vuln_scan.nikto_scan, target=target, port=port, use_tls=use_tls)


@mcp.tool()
def nmap_vuln_scripts(target: str, ports: str = "1-1024") -> dict:
    """Run nmap's NSE 'vuln' script category against an allowlisted target
    (detection only, not exploitation — checks for known CVEs/misconfigs
    like heartbleed, ms17-010, etc.).

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list.
    """
    return _safe_call(vuln_scan.nmap_vuln_scripts, target=target, ports=ports)


@mcp.tool()
def security_header_check(target: str, port: int = 80, use_tls: bool = False) -> dict:
    """Check an allowlisted target's web service for common security
    headers (HSTS, CSP, X-Frame-Options, etc.). Informational only —
    absence of a header is a hardening note, not proof of a vuln.

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list.
    """
    return _safe_call(vuln_scan.security_header_check, target=target, port=port, use_tls=use_tls)


# ---------------------------------------------------------------------------
# Exploit research tools — WARNING: EXPLOIT TOOLING
#
# These do NOT have an input()-based confirmation gate (stdio has no
# terminal to prompt). The human checkpoint for these three tools is
# YOUR MCP CLIENT'S own per-call approval UI. Confirm your client
# actually prompts you before each call before trusting that gate.
# ---------------------------------------------------------------------------

@mcp.tool()
def searchsploit_query(query: str) -> dict:
    """WARNING: EXPLOIT TOOLING. Read-only lookup against the local
    exploit-db mirror (searchsploit). Does not touch any target. This
    tool has no built-in confirmation step — your MCP client must
    prompt you for approval before this executes, or it will run
    unattended.

    query: search term, e.g. "vsftpd 2.3.4".
    """
    return _safe_call(exploit.searchsploit_query, query=query)


@mcp.tool()
def msf_search(query: str) -> dict:
    """WARNING: EXPLOIT TOOLING. Read-only search of the local Metasploit
    module index. Lists matching modules only; does not load, configure,
    or run any of them, and does not touch any target. This tool has no
    built-in confirmation step — your MCP client must prompt you for
    approval before this executes, or it will run unattended.

    query: search term for msfconsole's `search` command.
    """
    return _safe_call(exploit.msf_search, query=query)


@mcp.tool()
def generate_reverse_shell(lhost: str, lport: int, shell_type: str, intended_target: str) -> dict:
    """WARNING: EXPLOIT TOOLING. Generates reverse-shell payload TEXT
    only. Does NOT execute anything, does NOT connect to any target,
    does NOT touch the network in any way. This tool has no built-in
    confirmation step — your MCP client must prompt you for approval
    before this executes, or it will run unattended.

    lhost: YOUR listener IP. Must be private/loopback — this generator
        refuses to build payloads pointed at public IPs.
    lport: listener port, 1-65535.
    shell_type: one of bash, python3, nc, nc_mkfifo, powershell.
    intended_target: which allowlisted device this is intended for
        (tagging/logging only — no network action taken). Allowlisted
        targets ONLY — see config/allowlist.json for the configured
        device list.
    """
    return _safe_call(
        exploit.generate_reverse_shell,
        lhost=lhost,
        lport=lport,
        shell_type=shell_type,
        intended_target=intended_target,
    )


# ---------------------------------------------------------------------------
# Reporting tools
# ---------------------------------------------------------------------------

@mcp.tool()
def log_finding(
    target: str,
    source_tool: str,
    severity: str,
    title: str,
    description: str,
    evidence: str = "",
) -> dict:
    """Log a finding against an allowlisted target into the local SQLite
    findings DB.

    Allowlisted targets ONLY — see config/allowlist.json for the configured device list.
    severity: one of info, low, medium, high, critical.

    IMPORTANT for the calling model: only log a finding that is directly
    supported by an actual tool result you already have — do not log
    speculative or inferred findings. Quote the specific evidence (raw
    tool output) in the evidence field rather than paraphrasing it.
    """
    return _safe_call(
        reporting.log_finding,
        target=target,
        source_tool=source_tool,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
    )


@mcp.tool()
def list_findings(target: str | None = None, severity: str | None = None) -> list[dict]:
    """List logged findings, optionally filtered by target and/or severity.

    Allowlisted targets ONLY if target is provided — see
    config/allowlist.json for the configured device list.
    """
    try:
        return reporting.list_findings(target=target, severity=severity)
    except (NotAllowedError, InvalidInputError, ValueError) as exc:
        return [{"error": str(exc), "tool": "list_findings"}]


@mcp.tool()
def generate_markdown_report(title: str = "Personal Lab Red Team Report") -> dict:
    """Generate a Markdown report from all logged findings, written to
    ./reports/report_<timestamp>.md.
    """
    return _safe_call(reporting.generate_markdown_report, title=title)


if __name__ == "__main__":
    mcp.run()
