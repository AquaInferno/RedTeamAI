"""
vuln_scan.py
Vulnerability-scanning primitives, gated by tools.allowlist.ensure_allowed().

Same contract as recon.py:
  - allowlist check before anything else
  - sanitized args
  - list-form subprocess, no shell=True
  - plain dict results
"""

from __future__ import annotations

from datetime import datetime, timezone

from .allowlist import ensure_allowed, sanitize_token, run_cmd, label_for
from .recon import http_headers


def _envelope(target: str, tool: str, result: dict) -> dict:
    return {
        "tool": tool,
        "target": target,
        "target_label": label_for(target),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }


def nikto_scan(target: str, port: int = 80, use_tls: bool = False, timeout: int = 600) -> dict:
    """
    Run nikto against a web service on an allowlisted target.
    Nikto is noisy and slow by design (it's throwing a large known-issue
    checklist at the target), hence the generous default timeout.
    """
    target = ensure_allowed(target)

    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port must be an int in 1..65535, got {port!r}")

    argv = ["nikto", "-h", target, "-p", str(port)]
    if use_tls:
        argv += ["-ssl"]

    result = run_cmd(argv, timeout=timeout)
    return _envelope(target, "nikto_scan", result)


def nmap_vuln_scripts(target: str, ports: str = "1-1024") -> dict:
    """
    Run nmap's NSE 'vuln' script category against an allowlisted target.
    This checks for a curated set of well-known CVEs/misconfigs nmap's
    script engine knows how to fingerprint (heartbleed, ms17-010, etc.)
    — read-only detection, not exploitation.
    """
    target = ensure_allowed(target)
    ports = sanitize_token(ports, "ports")

    argv = ["nmap", "-sV", "--script", "vuln", "-p", ports, target]
    result = run_cmd(argv, timeout=600)
    return _envelope(target, "nmap_vuln_scripts", result)


# Headers commonly checked as a lightweight "is this web service hardened"
# signal. Presence/absence is informational, not a finding by itself.
_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def security_header_check(target: str, port: int = 80, use_tls: bool = False, path: str = "/") -> dict:
    """
    Fetch headers (reusing recon.http_headers) and flag which common
    security headers are present vs. missing. Purely informational —
    absence of a header is a hardening note, not proof of a vuln.
    """
    target = ensure_allowed(target)

    raw = http_headers(target, port=port, use_tls=use_tls, path=path)
    stdout = raw.get("stdout", "") or ""

    present = []
    missing = []
    for header in _SECURITY_HEADERS:
        if header.lower() + ":" in stdout.lower():
            present.append(header)
        else:
            missing.append(header)

    return _envelope(
        target,
        "security_header_check",
        {
            "port": port,
            "raw_headers": stdout,
            "present": present,
            "missing": missing,
        },
    )
