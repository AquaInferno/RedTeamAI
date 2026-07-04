"""
allowlist.py
Centralized target allowlist + safe subprocess execution helpers.

Every tool module (recon, vuln_scan, exploit, reporting) imports
`ensure_allowed()` and `run_cmd()` from here so the safety logic
lives in exactly one place instead of being duplicated per-file.

SCOPE CONFIG: the actual allowlist is loaded from config/allowlist.json
(untracked in git — see config/allowlist.example.json for the template).
This means every deployment of this project — a new VM, a friend's own
install, a fresh partition — sets ITS OWN scope pointing at devices that
installation's operator actually owns, instead of silently inheriting
whatever IPs were hardcoded when the code was written. There is no
supported way to disable this check; every tool in this project depends
on it to stay scoped to devices you're authorized to test.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class NotAllowedError(Exception):
    """Raised when a target is not in the allowlist."""


class InvalidInputError(Exception):
    """Raised when an argument fails sanitization."""


class ScopeConfigError(Exception):
    """Raised when config/allowlist.json is missing or malformed."""


@dataclass(frozen=True)
class AllowedTarget:
    ip: str
    label: str


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PATH = _PROJECT_ROOT / "config" / "allowlist.json"


def _load_allowlist() -> list[AllowedTarget]:
    if not _CONFIG_PATH.exists():
        raise ScopeConfigError(
            f"No scope configured: {_CONFIG_PATH} does not exist.\n"
            f"This project refuses to run without an explicit, deliberately-created "
            f"scope file — there is no default/fallback allowlist.\n"
            f"Create it by copying the template and editing it to list ONLY devices "
            f"YOU own and are authorized to test:\n"
            f"    cp {_PROJECT_ROOT / 'config' / 'allowlist.example.json'} {_CONFIG_PATH}\n"
            f"    # then edit config/allowlist.json with your own device IPs"
        )

    try:
        raw = json.loads(_CONFIG_PATH.read_text())
    except json.JSONDecodeError as exc:
        raise ScopeConfigError(f"config/allowlist.json is not valid JSON: {exc}")

    if not isinstance(raw, list) or not raw:
        raise ScopeConfigError(
            "config/allowlist.json must be a non-empty JSON array of "
            '{"ip": "...", "label": "..."} objects.'
        )

    targets = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict) or "ip" not in entry or "label" not in entry:
            raise ScopeConfigError(
                f"config/allowlist.json entry {i} must be an object with "
                '"ip" and "label" keys, got: {entry!r}'
            )
        try:
            ipaddress.ip_address(entry["ip"])
        except ValueError:
            raise ScopeConfigError(
                f"config/allowlist.json entry {i} has an invalid IP: {entry['ip']!r}"
            )
        targets.append(AllowedTarget(entry["ip"], entry["label"]))

    return targets


# ---------------------------------------------------------------------------
# THE allowlist. Loaded once at import time from config/allowlist.json.
# To change scope: edit that file (NOT this one) and restart the process
# (ai_controller.py, orchestrator.py, or whatever imported this module).
# ---------------------------------------------------------------------------
ALLOWLIST: list[AllowedTarget] = _load_allowlist()

_ALLOWED_IPS = {t.ip for t in ALLOWLIST}

# Conservative pattern for hostnames/IPs we're willing to even look at.
# (We still require the resolved/given IP to be in _ALLOWED_IPS below —
# this regex just blocks obviously-malformed or shell-metacharacter input.)
_TARGET_RE = re.compile(r"^[A-Za-z0-9.\-]{1,255}$")


def ensure_allowed(target: str) -> str:
    """
    Validate that `target` is one of the explicitly allowlisted IPs.

    Returns the validated target string on success.
    Raises NotAllowedError / InvalidInputError otherwise.

    NOTE: This intentionally does NOT resolve hostnames and check the
    resolved IP against the allowlist, because DNS resolution is itself
    something a hostile input could abuse. Only literal allowlisted IPs
    are accepted. If you want to scan by hostname, add a static mapping
    here explicitly rather than resolving at call time.
    """
    if not isinstance(target, str) or not _TARGET_RE.match(target):
        raise InvalidInputError(f"Rejected malformed target: {target!r}")

    try:
        ipaddress.ip_address(target)
    except ValueError:
        raise NotAllowedError(
            f"Target {target!r} is not a literal IP. Only allowlisted "
            f"literal IPs are accepted: {sorted(_ALLOWED_IPS)}"
        )

    if target not in _ALLOWED_IPS:
        raise NotAllowedError(
            f"Target {target!r} is NOT in the allowlist. "
            f"Allowed targets: {sorted(_ALLOWED_IPS)}"
        )

    return target


def label_for(target: str) -> str:
    for t in ALLOWLIST:
        if t.ip == target:
            return t.label
    return "unknown"


# Safe-ish token pattern for free-text args that get interpolated into
# command argv (ports, flags, script names). Deliberately restrictive.
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._,\-/:]{1,512}$")


def sanitize_token(value: str, field_name: str = "value") -> str:
    if not isinstance(value, str) or not _SAFE_TOKEN_RE.match(value):
        raise InvalidInputError(f"Rejected malformed {field_name}: {value!r}")
    return value


def run_cmd(
    argv: list[str],
    timeout: int = 120,
) -> dict:
    """
    Run a command via list-form subprocess (no shell=True), capture output,
    and return a structured result. Never raises on non-zero exit — callers
    inspect `returncode` themselves — but DOES raise on timeout since that's
    an operational signal worth surfacing distinctly.

    argv[0] should be a bare executable name (e.g. "nmap"); we do not
    accept shell strings anywhere in this codebase.
    """
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise InvalidInputError(f"argv must be a non-empty list[str], got {argv!r}")

    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {
            "argv": argv,
            "returncode": None,
            "stdout": "",
            "stderr": f"executable not found: {argv[0]}",
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "argv": argv,
            "returncode": None,
            "stdout": "",
            "stderr": f"command timed out after {timeout}s",
            "timed_out": True,
        }

    return {
        "argv": argv,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "timed_out": False,
    }
