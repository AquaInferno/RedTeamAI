"""
recon.py
Passive/active recon primitives, gated by tools.allowlist.ensure_allowed().

Every public function here:
  1. Validates its target against the allowlist FIRST, before touching
     the network.
  2. Sanitizes any other user-supplied arguments.
  3. Shells out via list-form subprocess.run (no shell=True).
  4. Returns a plain dict (never raises for "command failed", only for
     scope/input violations) so callers — including an LLM tool-calling
     layer — get a consistent, inspectable result shape.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

from .allowlist import ensure_allowed, sanitize_token, run_cmd, label_for


def _envelope(target: str, tool: str, result: dict) -> dict:
    return {
        "tool": tool,
        "target": target,
        "target_label": label_for(target),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }


def nmap_scan(target: str, ports: str = "1-1024", scan_type: str = "-sT") -> dict:
    """
    Run an nmap scan against an allowlisted target.

    target:    literal allowlisted IP.
    ports:     nmap port spec, e.g. "1-1024", "22,80,443", "1-65535".
    scan_type: one of a small safe set (default TCP connect scan).
               SYN scan (-sS) requires root/cap_net_raw; allowed here
               since this runs on your own Kali box against your own
               devices, but kept as an explicit opt-in.
    """
    target = ensure_allowed(target)
    ports = sanitize_token(ports, "ports")

    allowed_scan_types = {"-sT", "-sS", "-sU", "-sV", "-A"}
    if scan_type not in allowed_scan_types:
        raise ValueError(
            f"scan_type {scan_type!r} not permitted; choose from {sorted(allowed_scan_types)}"
        )

    argv = ["nmap", scan_type, "-p", ports, "-T4", "--open", target]
    result = run_cmd(argv, timeout=300)
    return _envelope(target, "nmap_scan", result)


def dig_lookup(target: str, record_type: str = "A") -> dict:
    """
    DNS lookup via dig. Only meaningful for allowlisted targets that
    have a reverse/forward DNS entry on your own network, but we still
    validate `target` against the allowlist for consistency — this
    queries records *for* the target IP (PTR by default makes sense;
    A/AAAA/TXT etc. also supported for completeness).
    """
    target = ensure_allowed(target)

    allowed_types = {"A", "AAAA", "TXT", "MX", "NS", "PTR", "SOA"}
    record_type = record_type.upper()
    if record_type not in allowed_types:
        raise ValueError(f"record_type {record_type!r} not permitted; choose from {sorted(allowed_types)}")

    if record_type == "PTR":
        argv = ["dig", "-x", target, "+short"]
    else:
        argv = ["dig", target, record_type, "+short"]

    result = run_cmd(argv, timeout=30)
    return _envelope(target, "dig_lookup", result)


def whois_lookup(target: str) -> dict:
    """
    WHOIS lookup. Note: for RFC1918 private addresses (192.168.x.x),
    WHOIS servers will typically return "not allocated to you" / IANA
    reserved-space info rather than anything useful — this is included
    for architectural completeness (e.g. if the allowlist is later
    extended to include a public-facing asset you own).
    """
    target = ensure_allowed(target)
    argv = ["whois", target]
    result = run_cmd(argv, timeout=30)
    return _envelope(target, "whois_lookup", result)


def banner_grab(target: str, port: int, timeout: float = 3.0) -> dict:
    """
    Raw TCP connect + banner read (no external binary — uses the socket
    module directly). Sends nothing; just reads whatever the service
    volunteers on connect, which is what most banner-grab tools do for
    the initial handshake-free grab.
    """
    target = ensure_allowed(target)

    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port must be an int in 1..65535, got {port!r}")

    banner = ""
    error = None
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = ""
    except (ConnectionRefusedError, OSError) as exc:
        error = str(exc)

    return _envelope(
        target,
        "banner_grab",
        {
            "port": port,
            "banner": banner,
            "error": error,
        },
    )


def http_headers(target: str, port: int = 80, use_tls: bool = False, path: str = "/") -> dict:
    """
    Fetch HTTP response headers via curl -I (list-form, no shell).
    Useful for quick "what's this web service" checks ahead of nikto.
    """
    target = ensure_allowed(target)

    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port must be an int in 1..65535, got {port!r}")
    path = sanitize_token(path, "path") if path != "/" else "/"

    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{target}:{port}{path}"

    argv = ["curl", "-s", "-I", "-k", "--max-time", "10", url]
    result = run_cmd(argv, timeout=15)
    return _envelope(target, "http_headers", result)
