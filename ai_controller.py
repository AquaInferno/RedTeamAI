"""
ai_controller.py
Standalone Ollama-driven controller — no MCP involved. This exists to
test the tool-calling loop and the tool modules directly, before
wrapping them in orchestrator.py (the actual MCP server, stage 4).

Requires a tool-calling-capable Ollama model. Vanilla llama3.1:8b supports
tools= out of the box, which is what this defaults to.

Run:
    python3 ai_controller.py
    python3 ai_controller.py --model llama3.1:8b
    python3 ai_controller.py --host http://localhost:11434

Safety model:
  - Every tool function still does its own allowlist/sanitization
    checks (see tools/allowlist.py) — the controller is not a trust
    boundary by itself, it's a second layer.
  - Anything in tools/exploit.py additionally requires an explicit
    y/n confirmation typed by YOU in this terminal before it runs,
    regardless of what the model requested. Recon/vuln_scan/reporting
    tools execute automatically since they're read-only or pure
    logging.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable

import requests

from tools import recon, vuln_scan, exploit, reporting
from tools.allowlist import ALLOWLIST, NotAllowedError, InvalidInputError

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"

CONFIRM_REQUIRED_TOOLS = {
    "searchsploit_query",
    "msf_search",
    "generate_reverse_shell",
}


# ---------------------------------------------------------------------------
# Tool registry: name -> callable, plus the JSON schema Ollama needs to
# know how/when to call each one.
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "nmap_scan": recon.nmap_scan,
    "dig_lookup": recon.dig_lookup,
    "whois_lookup": recon.whois_lookup,
    "banner_grab": recon.banner_grab,
    "http_headers": recon.http_headers,
    "nikto_scan": vuln_scan.nikto_scan,
    "nmap_vuln_scripts": vuln_scan.nmap_vuln_scripts,
    "security_header_check": vuln_scan.security_header_check,
    "searchsploit_query": exploit.searchsploit_query,
    "msf_search": exploit.msf_search,
    "generate_reverse_shell": exploit.generate_reverse_shell,
    "log_finding": reporting.log_finding,
    "list_findings": reporting.list_findings,
    "generate_markdown_report": reporting.generate_markdown_report,
}

_ALLOWED_IPS = [t.ip for t in ALLOWLIST]

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": "Run an nmap scan against an allowlisted target IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "ports": {"type": "string", "description": "e.g. '1-1024' or '22,80,443'"},
                    "scan_type": {"type": "string", "enum": ["-sT", "-sS", "-sU", "-sV", "-A"]},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dig_lookup",
            "description": "DNS lookup against an allowlisted target IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "record_type": {"type": "string", "enum": ["A", "AAAA", "TXT", "MX", "NS", "PTR", "SOA"]},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "whois_lookup",
            "description": "WHOIS lookup for an allowlisted target IP.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string", "enum": _ALLOWED_IPS}},
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "banner_grab",
            "description": "Connect to a TCP port on an allowlisted target and read the service banner.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "port": {"type": "integer"},
                },
                "required": ["target", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_headers",
            "description": "Fetch HTTP response headers from an allowlisted target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "port": {"type": "integer"},
                    "use_tls": {"type": "boolean"},
                    "path": {"type": "string"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_scan",
            "description": "Run nikto web vuln scan against an allowlisted target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "port": {"type": "integer"},
                    "use_tls": {"type": "boolean"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_vuln_scripts",
            "description": "Run nmap NSE 'vuln' script category against an allowlisted target (detection only).",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "ports": {"type": "string"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "security_header_check",
            "description": "Check an allowlisted target's web service for common security headers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "port": {"type": "integer"},
                    "use_tls": {"type": "boolean"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "searchsploit_query",
            "description": "Search local exploit-db mirror for known exploits matching a query, e.g. 'vsftpd 2.3.4'. Read-only lookup, requires user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "msf_search",
            "description": "Search local Metasploit module index for a query. Read-only lookup, requires user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_reverse_shell",
            "description": (
                "Generate reverse-shell payload TEXT (does not execute anything). "
                "lhost must be a private/loopback IP. intended_target must be an "
                "allowlisted device. Requires user confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "lhost": {"type": "string"},
                    "lport": {"type": "integer"},
                    "shell_type": {
                        "type": "string",
                        "enum": ["bash", "python3", "nc", "nc_mkfifo", "powershell"],
                    },
                    "intended_target": {"type": "string", "enum": _ALLOWED_IPS},
                },
                "required": ["lhost", "lport", "shell_type", "intended_target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "log_finding",
            "description": "Log a finding against an allowlisted target into the local findings DB.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "source_tool": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["target", "source_tool", "severity", "title", "description"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_findings",
            "description": "List logged findings, optionally filtered by target and/or severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": _ALLOWED_IPS},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_markdown_report",
            "description": "Generate a Markdown report from all logged findings.",
            "parameters": {
                "type": "object",
                "properties": {"title": {"type": "string"}},
                "required": [],
            },
        },
    },
]


SYSTEM_PROMPT = f"""You are a personal red-team lab assistant. You may ONLY operate \
against these explicitly allowlisted devices, all owned by the operator: \
{', '.join(f'{t.ip} ({t.label})' for t in ALLOWLIST)}.

Never attempt to scan, probe, or generate payloads for any other IP, hostname, \
or "similar" address. If asked to act outside this allowlist, refuse and explain \
that only the operator's own devices are in scope. Every tool call is independently \
validated against this same allowlist server-side, so out-of-scope requests will be \
rejected regardless, but you should not attempt them in the first place.

This is a personal lab. There is no client, no signed scope of work beyond this \
allowlist, and no authorization to touch anything else.

CRITICAL — do not hallucinate findings. When you summarize a tool result, you may \
ONLY state facts that are literally present in that tool's stdout/output field. \
Never infer, assume, or invent a port, service, banner, or vulnerability that is \
not explicitly shown in the output. If an nmap scan's stdout contains no PORT/STATE \
table, that means no open ports were found in the scanned range — say exactly that \
("no open ports found in the scanned range"), do not guess common ports like 22 or \
80 are open. If you are not sure whether something is present in the output, quote \
the relevant line directly rather than paraphrasing from memory of what a typical \
scan looks like.

Service/product names from tool output (e.g. nmap's SERVICE column, banner text) \
must be copied VERBATIM, character for character, exactly as printed. Do not \
translate, expand, or "clean up" a raw service name into a more familiar-sounding \
one — for example, "msrpc" must be reported as "msrpc", never rewritten as \
"Microsoft-DS", "RPC service", or any other paraphrase, even if it seems like a \
reasonable guess at what the abbreviation means. If you want to explain what a \
service name means in plain language, do so as a clearly separate note AFTER \
quoting the verbatim name, not as a substitute for it."""


def _confirm(prompt: str) -> bool:
    resp = input(f"{prompt} [y/N]: ").strip().lower()
    return resp == "y"


def dispatch_tool_call(name: str, arguments: dict) -> dict:
    """
    Execute a single tool call by name, with a human confirmation gate
    for exploit-related tools. Never raises — always returns a dict
    suitable for feeding back to the model, including on error, so a
    scope violation or bad arg becomes model-visible feedback instead
    of crashing the loop.
    """
    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}

    if name in CONFIRM_REQUIRED_TOOLS:
        print(f"\n[confirmation required] model wants to call {name}({arguments})")
        if not _confirm("Allow this exploit-tooling call?"):
            return {"error": "denied by operator", "tool": name}

    try:
        result = fn(**arguments)
        return result
    except (NotAllowedError, InvalidInputError, ValueError) as exc:
        return {"error": str(exc), "tool": name}
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}", "tool": name}


def _ollama_chat(host: str, model: str, messages: list[dict]) -> dict:
    resp = requests.post(
        f"{host}/api/chat",
        json={
            "model": model,
            "messages": messages,
            "tools": TOOL_SCHEMAS,
            "stream": False,
        },
        timeout=180,
    )
    if not resp.ok:
        # Ollama puts the actual reason in the response body (e.g. "model
        # does not support tools", "model not found"), which a bare
        # raise_for_status() would otherwise swallow.
        try:
            detail = resp.json().get("error", resp.text)
        except ValueError:
            detail = resp.text
        raise RuntimeError(f"HTTP {resp.status_code} from Ollama: {detail}")
    return resp.json()


def run_repl(host: str, model: str) -> None:
    print(f"ai_controller.py — model={model} host={host}")
    print(f"Allowlisted targets: {', '.join(f'{t.ip} ({t.label})' for t in ALLOWLIST)}")
    print("Type 'exit' or 'quit' to stop.\n")

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

    while True:
        try:
            user_input = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if user_input.lower() in {"exit", "quit"}:
            break
        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})

        # Tool-calling loop: keep going as long as the model keeps
        # requesting tool calls, feeding results back each time.
        for _ in range(8):  # hard cap so a misbehaving model can't loop forever
            try:
                data = _ollama_chat(host, model, messages)
            except requests.exceptions.ConnectionError:
                print(f"[error] could not reach Ollama at {host} — is it running?")
                messages.pop()  # drop the unanswered user turn
                break
            except RuntimeError as exc:
                print(f"[error] {exc}")
                messages.pop()
                break

            msg = data.get("message", {})
            tool_calls = msg.get("tool_calls") or []

            if not tool_calls:
                content = msg.get("content", "")
                print(f"assistant> {content}\n")
                messages.append({"role": "assistant", "content": content})
                break

            messages.append(msg)

            for call in tool_calls:
                fn_name = call["function"]["name"]
                raw_args = call["function"].get("arguments", {})
                if isinstance(raw_args, str):
                    try:
                        raw_args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        raw_args = {}

                print(f"[tool call] {fn_name}({raw_args})")
                result = dispatch_tool_call(fn_name, raw_args)
                print(f"[tool result] {json.dumps(result, indent=2)[:2000]}\n")

                messages.append(
                    {
                        "role": "tool",
                        "content": json.dumps(result),
                    }
                )
        else:
            print("[warning] hit max tool-call iterations for this turn; stopping.\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone Ollama-driven red team lab controller")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Ollama host (default: {DEFAULT_HOST})")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    args = parser.parse_args()

    if "dolphin" in args.model.lower():
        print(
            f"[warning] {args.model!r} looks like a dolphin-llama3-based model. "
            "Those don't support tools= in Ollama — tool calls won't work. "
            "Use a tool-calling-capable model (e.g. llama3.1:8b) instead."
        )

    run_repl(args.host, args.model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
