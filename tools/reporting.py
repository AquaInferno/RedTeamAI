"""
reporting.py
Local finding log + report generation. SQLite-backed (stdlib only,
no extra deps), stored under ./reports/findings.db relative to the
project root by default.

This module doesn't touch the network or the allowlist-gated tools at
all — it just records what other tools found and turns that into a
readable report.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from .allowlist import ensure_allowed, label_for, InvalidInputError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
DB_PATH = REPORTS_DIR / "findings.db"

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_label TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,
    created_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class Finding:
    id: int
    target: str
    target_label: str
    source_tool: str
    severity: str
    title: str
    description: str
    evidence: str
    created_at: str


@contextmanager
def _db():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def log_finding(
    target: str,
    source_tool: str,
    severity: str,
    title: str,
    description: str,
    evidence: str = "",
) -> dict:
    """
    Record a finding against an allowlisted target. This is the one
    write-path in the whole reporting module, and it's gated the same
    way every network-touching tool is — you can't log a finding
    against something outside your scope, which keeps the eventual
    report honest about what was actually in scope.
    """
    target = ensure_allowed(target)

    severity = severity.lower()
    if severity not in _VALID_SEVERITIES:
        raise InvalidInputError(
            f"severity {severity!r} not valid; choose from {sorted(_VALID_SEVERITIES)}"
        )

    if not title or not isinstance(title, str):
        raise InvalidInputError("title must be a non-empty string")
    if not description or not isinstance(description, str):
        raise InvalidInputError("description must be a non-empty string")

    now = datetime.now(timezone.utc).isoformat()
    target_label = label_for(target)

    with _db() as conn:
        cur = conn.execute(
            """
            INSERT INTO findings
                (target, target_label, source_tool, severity, title, description, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (target, target_label, source_tool, severity, title, description, evidence, now),
        )
        finding_id = cur.lastrowid

    return {
        "tool": "log_finding",
        "finding_id": finding_id,
        "target": target,
        "target_label": target_label,
        "severity": severity,
        "title": title,
        "created_at": now,
    }


def list_findings(target: str | None = None, severity: str | None = None) -> list[dict]:
    """
    List logged findings, optionally filtered by target (must be
    allowlisted if provided) and/or severity.
    """
    if target is not None:
        target = ensure_allowed(target)
    if severity is not None:
        severity = severity.lower()
        if severity not in _VALID_SEVERITIES:
            raise InvalidInputError(
                f"severity {severity!r} not valid; choose from {sorted(_VALID_SEVERITIES)}"
            )

    query = "SELECT * FROM findings WHERE 1=1"
    params: list[str] = []
    if target is not None:
        query += " AND target = ?"
        params.append(target)
    if severity is not None:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY created_at DESC"

    with _db() as conn:
        rows = conn.execute(query, params).fetchall()

    return [dict(row) for row in rows]


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def generate_markdown_report(title: str = "Personal Lab Red Team Report") -> dict:
    """
    Render all logged findings into a Markdown report, grouped by
    target then severity, and write it to ./reports/report_<ts>.md.
    """
    findings = list_findings()

    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    report_path = REPORTS_DIR / f"report_{ts}.md"

    by_target: dict[str, list[dict]] = {}
    for f in findings:
        by_target.setdefault(f["target"], []).append(f)

    lines = [
        f"# {title}",
        "",
        f"_Generated: {now.isoformat()}_",
        "",
        "**Scope:** personal lab devices only (see `tools/allowlist.py`). "
        "No client work without a signed scope of work.",
        "",
        f"**Total findings:** {len(findings)}",
        "",
    ]

    for target, items in by_target.items():
        label = label_for(target)
        lines.append(f"## {label} ({target})")
        lines.append("")
        items_by_sev = sorted(
            items, key=lambda f: _SEVERITY_ORDER.index(f["severity"])
        )
        for f in items_by_sev:
            lines.append(f"### [{f['severity'].upper()}] {f['title']}")
            lines.append("")
            lines.append(f"- **Source tool:** {f['source_tool']}")
            lines.append(f"- **Logged:** {f['created_at']}")
            lines.append("")
            lines.append(f["description"])
            if f["evidence"]:
                lines.append("")
                lines.append("```")
                lines.append(f["evidence"])
                lines.append("```")
            lines.append("")

    if not findings:
        lines.append("_No findings logged yet._")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")

    return {
        "tool": "generate_markdown_report",
        "report_path": str(report_path),
        "finding_count": len(findings),
        "targets_covered": list(by_target.keys()),
    }
