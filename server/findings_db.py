"""SQLite findings database with 7-table schema for cross-session persistence.

Schema:
  engagements  -> hosts -> services
               -> vulns
               -> credentials
               -> chains
               -> session_log

Port of pentest-ai-agents' findings.sh approach as a Python module.
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crypto_utils import decrypt_secret, encrypt_secret

logger = logging.getLogger("dristi-findings-db")


# ── Schema ───────────────────────────────────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    client TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'web',
    scope TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    start_date TEXT NOT NULL,
    end_date TEXT,
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    ip TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_by TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    UNIQUE(engagement_id, ip, hostname)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    banner TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    host_id INTEGER REFERENCES hosts(id),
    finding_ref TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    cvss REAL DEFAULT 0.0,
    cve TEXT NOT NULL DEFAULT '',
    mitre_id TEXT NOT NULL DEFAULT '',
    test_id TEXT NOT NULL DEFAULT '',
    tool_used TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    poc_output TEXT NOT NULL DEFAULT '',
    affected_url TEXT NOT NULL DEFAULT '',
    affected_parameter TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    host_id INTEGER REFERENCES hosts(id),
    username TEXT NOT NULL DEFAULT '',
    secret TEXT NOT NULL DEFAULT '',
    secret_type TEXT NOT NULL DEFAULT 'password',
    domain TEXT NOT NULL DEFAULT '',
    access_level TEXT NOT NULL DEFAULT 'unknown',
    valid INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    name TEXT NOT NULL,
    score REAL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'draft',
    steps TEXT NOT NULL DEFAULT '[]',
    mitre_ids TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    agent TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON hosts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_engagement ON vulns(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulns(status);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulns(cve);
CREATE INDEX IF NOT EXISTS idx_vulns_tool ON vulns(tool_used);
CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_chains_engagement ON chains(engagement_id);
CREATE INDEX IF NOT EXISTS idx_session_log_engagement ON session_log(engagement_id);
"""


# ── Database Manager ─────────────────────────────────────────────────────────
class FindingsDB:
    """Thread-safe SQLite findings database."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._closed = False
        self._init_schema()

    def close(self) -> None:
        self._closed = True
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path))
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_schema(self) -> None:
        """Create schema if not exists."""
        conn = self._get_conn()
        conn.executescript(SCHEMA_SQL)
        # Check if schema version is recorded
        cur = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        if not row or row[0] is None:
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (1, _now_iso()),
            )
        conn.commit()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self._get_conn()
        return conn.execute(sql, params)

    def _fetchone(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._execute(sql, params).fetchone()

    def _fetchall(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self._execute(sql, params).fetchall()

    def _row_to_dict(self, row: sqlite3.Row | None) -> dict:
        if row is None:
            return {}
        return dict(row)

    def _rows_to_list(self, rows: list[sqlite3.Row]) -> list[dict]:
        return [dict(r) for r in rows]

    # ── Engagements ──────────────────────────────────────────────────────

    def init_engagement(
        self,
        engagement_id: str,
        client: str = "",
        etype: str = "web",
        scope: str = "",
        notes: str = "",
    ) -> dict:
        """Create a new engagement. Returns the engagement dict."""
        existing = self._fetchone("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
        if existing:
            return self._row_to_dict(existing)
        self._execute(
            """INSERT INTO engagements (id, client, type, scope, status, start_date, notes)
               VALUES (?, ?, ?, ?, 'active', ?, ?)""",
            (engagement_id, client, etype, scope, _now_iso(), notes),
        )
        self._get_conn().commit()
        return self.get_engagement(engagement_id)

    def get_engagement(self, engagement_id: str) -> dict:
        row = self._fetchone("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
        return self._row_to_dict(row)

    def list_engagements(self, status: str = "") -> list[dict]:
        if status:
            return self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM engagements WHERE status = ? ORDER BY start_date DESC",
                    (status,),
                )
            )
        return self._rows_to_list(self._fetchall("SELECT * FROM engagements ORDER BY start_date DESC"))

    def update_engagement(self, engagement_id: str, **kwargs) -> dict:
        allowed = {"client", "type", "scope", "status", "end_date", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v}
        if not updates:
            return self.get_engagement(engagement_id)
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [engagement_id]
        self._execute(f"UPDATE engagements SET {sets} WHERE id = ?", tuple(vals))
        self._get_conn().commit()
        return self.get_engagement(engagement_id)

    def close_engagement(self, engagement_id: str) -> dict:
        return self.update_engagement(engagement_id, status="closed", end_date=_now_iso())

    # ── Hosts ────────────────────────────────────────────────────────────

    def add_host(
        self,
        engagement_id: str,
        ip: str = "",
        hostname: str = "",
        os: str = "",
        role: str = "",
        discovered_by: str = "",
        notes: str = "",
    ) -> dict:
        existing = self._fetchone(
            "SELECT * FROM hosts WHERE engagement_id = ? AND ip = ? AND hostname = ?",
            (engagement_id, ip, hostname),
        )
        if existing:
            return self._row_to_dict(existing)
        self._execute(
            """INSERT INTO hosts (engagement_id, ip, hostname, os, role, status, discovered_by, notes)
               VALUES (?, ?, ?, ?, ?, 'discovered', ?, ?)""",
            (engagement_id, ip, hostname, os, role, discovered_by, notes),
        )
        self._get_conn().commit()
        row = self._fetchone(
            "SELECT * FROM hosts WHERE engagement_id = ? AND ip = ? AND hostname = ?",
            (engagement_id, ip, hostname),
        )
        return self._row_to_dict(row)

    def list_hosts(self, engagement_id: str) -> list[dict]:
        return self._rows_to_list(
            self._fetchall(
                "SELECT * FROM hosts WHERE engagement_id = ? ORDER BY ip",
                (engagement_id,),
            )
        )

    # ── Services ─────────────────────────────────────────────────────────

    def add_service(
        self,
        host_id: int,
        port: int,
        protocol: str = "tcp",
        service: str = "",
        version: str = "",
        banner: str = "",
        notes: str = "",
    ) -> dict:
        self._execute(
            """INSERT INTO services (host_id, port, protocol, service, version, banner, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (host_id, port, protocol, service, version, banner, notes),
        )
        self._get_conn().commit()
        row = self._fetchone("SELECT * FROM services WHERE id = last_insert_rowid()")
        return self._row_to_dict(row)

    def list_services(self, host_id: int = 0, engagement_id: str = "") -> list[dict]:
        if host_id:
            return self._rows_to_list(self._fetchall("SELECT * FROM services WHERE host_id = ?", (host_id,)))
        if engagement_id:
            return self._rows_to_list(
                self._fetchall(
                    """SELECT svc.* FROM services svc
                       JOIN hosts h ON svc.host_id = h.id
                       WHERE h.engagement_id = ?""",
                    (engagement_id,),
                )
            )
        return []

    # ── Vulnerabilities ──────────────────────────────────────────────────

    def add_vuln(
        self,
        engagement_id: str,
        title: str,
        severity: str = "medium",
        cvss: float = 0.0,
        cve: str = "",
        mitre_id: str = "",
        test_id: str = "",
        tool_used: str = "",
        affected_url: str = "",
        affected_parameter: str = "",
        description: str = "",
        evidence: str = "",
        poc_output: str = "",
        remediation: str = "",
        domain: str = "",
        host_id: int = 0,
        finding_ref: str = "",
    ) -> dict:
        now = _now_iso()
        # Auto-generate finding_ref if not provided
        if not finding_ref:
            count = self._fetchone(
                "SELECT COUNT(*) as c FROM vulns WHERE engagement_id = ?",
                (engagement_id,),
            )
            next_num = (count["c"] if count else 0) + 1
            finding_ref = f"FINDING-{next_num:03d}"
        self._execute(
            """INSERT INTO vulns
               (engagement_id, host_id, finding_ref, title, severity, cvss, cve, mitre_id,
                test_id, tool_used, status, affected_url, affected_parameter,
                description, evidence, poc_output, remediation, domain, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id,
                host_id or None,
                finding_ref,
                title,
                severity,
                cvss,
                cve,
                mitre_id,
                test_id,
                tool_used,
                affected_url,
                affected_parameter,
                description,
                evidence,
                poc_output,
                remediation,
                domain,
                now,
                now,
            ),
        )
        self._get_conn().commit()
        row = self._fetchone("SELECT * FROM vulns WHERE id = last_insert_rowid()")
        return self._row_to_dict(row)

    def get_vuln_by_ref(self, engagement_id: str, finding_ref: str) -> dict | None:
        row = self._fetchone(
            "SELECT * FROM vulns WHERE engagement_id = ? AND finding_ref = ?",
            (engagement_id, finding_ref),
        )
        return self._row_to_dict(row) if row else None

    def list_vulns(
        self,
        engagement_id: str = "",
        severity: str = "",
        status: str = "",
        tool_used: str = "",
    ) -> list[dict]:
        parts = ["SELECT * FROM vulns WHERE 1=1"]
        params = []
        if engagement_id:
            parts.append("AND engagement_id = ?")
            params.append(engagement_id)
        if severity:
            parts.append("AND severity = ?")
            params.append(severity)
        if status:
            parts.append("AND status = ?")
            params.append(status)
        if tool_used:
            parts.append("AND tool_used = ?")
            params.append(tool_used)
        parts.append("ORDER BY CASE severity " "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 " "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END")
        return self._rows_to_list(self._fetchall(" ".join(parts), tuple(params)))

    def update_vuln(self, vuln_id: int, **kwargs) -> dict:
        allowed = {
            "severity",
            "cvss",
            "cve",
            "mitre_id",
            "test_id",
            "tool_used",
            "status",
            "poc_output",
            "title",
            "description",
            "evidence",
            "remediation",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed and v}
        if not updates:
            row = self._fetchone("SELECT * FROM vulns WHERE id = ?", (vuln_id,))
            return self._row_to_dict(row)
        updates["updated_at"] = _now_iso()
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [vuln_id]
        self._execute(f"UPDATE vulns SET {sets} WHERE id = ?", tuple(vals))
        self._get_conn().commit()
        row = self._fetchone("SELECT * FROM vulns WHERE id = ?", (vuln_id,))
        return self._row_to_dict(row)

    # ── Credentials ──────────────────────────────────────────────────────

    def add_credential(
        self,
        engagement_id: str,
        username: str,
        secret: str,
        secret_type: str = "password",
        domain: str = "",
        access_level: str = "unknown",
        source: str = "",
        notes: str = "",
        host_id: int = 0,
    ) -> dict:
        encrypted = encrypt_secret(secret)
        self._execute(
            """INSERT INTO credentials
               (engagement_id, host_id, username, secret, secret_type, domain,
                access_level, valid, source, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (engagement_id, host_id or None, username, encrypted, secret_type, domain, access_level, source, notes),
        )
        self._get_conn().commit()
        row = self._fetchone("SELECT * FROM credentials WHERE id = last_insert_rowid()")
        result = self._row_to_dict(row)
        if "secret" in result:
            result["secret"] = decrypt_secret(result["secret"])
        return result

    def list_credentials(self, engagement_id: str = "") -> list[dict]:
        rows = []
        if engagement_id:
            rows = self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM credentials WHERE engagement_id = ?",
                    (engagement_id,),
                )
            )
        else:
            rows = self._rows_to_list(self._fetchall("SELECT * FROM credentials"))
        for r in rows:
            if "secret" in r:
                r["secret"] = decrypt_secret(r["secret"])
        return rows

    # ── Attack Chains ────────────────────────────────────────────────────

    def add_chain(
        self,
        engagement_id: str,
        name: str,
        score: float = 0.0,
        steps: list | str | None = None,
        mitre_ids: str = "",
        notes: str = "",
    ) -> dict:
        now = _now_iso()
        steps_json = json.dumps(steps or [])
        self._execute(
            """INSERT INTO chains
               (engagement_id, name, score, status, steps, mitre_ids, notes, created_at, updated_at)
               VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?)""",
            (engagement_id, name, score, steps_json, mitre_ids, notes, now, now),
        )
        self._get_conn().commit()
        row = self._fetchone("SELECT * FROM chains WHERE id = last_insert_rowid()")
        return self._row_to_dict(row)

    def list_chains(self, engagement_id: str = "") -> list[dict]:
        if engagement_id:
            return self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM chains WHERE engagement_id = ?",
                    (engagement_id,),
                )
            )
        return self._rows_to_list(self._fetchall("SELECT * FROM chains"))

    def update_chain(self, chain_id: int, **kwargs) -> dict:
        allowed = {"name", "score", "status", "steps", "mitre_ids", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if "steps" in updates and isinstance(updates["steps"], list):
            updates["steps"] = json.dumps(updates["steps"])
        if not updates:
            row = self._fetchone("SELECT * FROM chains WHERE id = ?", (chain_id,))
            return self._row_to_dict(row)
        updates["updated_at"] = _now_iso()
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [chain_id]
        self._execute(f"UPDATE chains SET {sets} WHERE id = ?", tuple(vals))
        self._get_conn().commit()
        row = self._fetchone("SELECT * FROM chains WHERE id = ?", (chain_id,))
        return self._row_to_dict(row)

    # ── Session Log ──────────────────────────────────────────────────────

    def log_action(
        self,
        engagement_id: str,
        agent: str = "",
        action: str = "",
        summary: str = "",
        detail: str = "",
    ) -> dict:
        self._execute(
            """INSERT INTO session_log (engagement_id, agent, action, summary, detail, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (engagement_id, agent, action, summary, detail, _now_iso()),
        )
        self._get_conn().commit()
        row = self._fetchone("SELECT * FROM session_log WHERE id = last_insert_rowid()")
        return self._row_to_dict(row)

    def get_session_log(self, engagement_id: str = "", limit: int = 50) -> list[dict]:
        if engagement_id:
            return self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM session_log WHERE engagement_id = ? ORDER BY created_at DESC LIMIT ?",
                    (engagement_id, limit),
                )
            )
        return self._rows_to_list(
            self._fetchall(
                "SELECT * FROM session_log ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        )

    # ── Stats & Export ───────────────────────────────────────────────────

    def stats(self, engagement_id: str) -> dict[str, Any]:
        data: dict[str, Any] = {
            "engagement": self.get_engagement(engagement_id),
        }
        host_count = self._fetchone(
            "SELECT COUNT(*) as c FROM hosts WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["hosts"] = host_count["c"] if host_count else 0
        svc_count = self._fetchone(
            """SELECT COUNT(*) as c FROM services svc
               JOIN hosts h ON svc.host_id = h.id
               WHERE h.engagement_id = ?""",
            (engagement_id,),
        )
        data["services"] = svc_count["c"] if svc_count else 0
        vuln_total = self._fetchone(
            "SELECT COUNT(*) as c FROM vulns WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["vulns"] = {"total": vuln_total["c"] if vuln_total else 0}
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            n = self._fetchone(
                "SELECT COUNT(*) as c FROM vulns WHERE engagement_id = ? AND severity = ?",
                (engagement_id, sev),
            )
            data["vulns"][sev.lower()] = n["c"] if n else 0
        cred_count = self._fetchone(
            "SELECT COUNT(*) as c FROM credentials WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["credentials"] = cred_count["c"] if cred_count else 0
        chain_count = self._fetchone(
            "SELECT COUNT(*) as c FROM chains WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["chains"] = chain_count["c"] if chain_count else 0
        log_count = self._fetchone(
            "SELECT COUNT(*) as c FROM session_log WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["session_entries"] = log_count["c"] if log_count else 0
        return data

    def export_json(self, engagement_id: str) -> str:
        data = {
            "engagement": self.get_engagement(engagement_id),
            "hosts": self.list_hosts(engagement_id),
            "services": self.list_services(engagement_id=engagement_id),
            "vulns": self.list_vulns(engagement_id=engagement_id),
            "credentials": self.list_credentials(engagement_id=engagement_id),
            "chains": self.list_chains(engagement_id=engagement_id),
            "session_log": self.get_session_log(engagement_id=engagement_id, limit=1000),
        }
        return json.dumps(data, indent=2, default=str)

    def handoff_markdown(self, engagement_id: str) -> str:
        """Generate a handoff report in Markdown for the next session."""
        eng = self.get_engagement(engagement_id)
        hosts = self.list_hosts(engagement_id)
        vulns = self.list_vulns(engagement_id=engagement_id)
        vulns_by_sev: dict[str, list] = {"Critical": [], "High": [], "Medium": [], "Low": [], "Informational": []}
        for v in vulns:
            vulns_by_sev.get(v["severity"], []).append(v)
        creds = self.list_credentials(engagement_id=engagement_id)
        chains = self.list_chains(engagement_id=engagement_id)
        log = self.get_session_log(engagement_id=engagement_id, limit=30)

        lines = []
        lines.append(f"# Engagement Handoff: {engagement_id}")
        lines.append("")
        lines.append(f"**Client:** {eng.get('client', 'N/A')}")
        lines.append(f"**Type:** {eng.get('type', 'N/A')}")
        lines.append(f"**Scope:** {eng.get('scope', 'N/A')}")
        lines.append(f"**Status:** {eng.get('status', 'N/A')}")
        lines.append(f"**Start:** {eng.get('start_date', 'N/A')}")
        if eng.get("end_date"):
            lines.append(f"**End:** {eng['end_date']}")
        lines.append("")

        # Hosts
        lines.append("## Hosts")
        lines.append("")
        lines.append("| IP | Hostname | OS | Role | Status |")
        lines.append("|----|----------|----|------|--------|")
        for h in hosts:
            lines.append(f"| {h['ip']} | {h['hostname']} | {h['os']} | {h['role']} | {h['status']} |")
        lines.append("")

        # Vulnerabilities
        lines.append("## Vulnerabilities")
        lines.append("")
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            items = vulns_by_sev.get(sev, [])
            if not items:
                continue
            lines.append(f"### {sev} ({len(items)})")
            lines.append("")
            lines.append("| ID | Title | URL | Status | Tool |")
            lines.append("|----|-------|-----|--------|------|")
            for v in items:
                vid = v.get("id", "")
                lines.append(f"| {vid} | {v['title']} | {v.get('affected_url', '')} " f"| {v.get('status', '')} | {v.get('tool_used', '')} |")
            lines.append("")

        # Credentials
        if creds:
            lines.append("## Credentials")
            lines.append("")
            lines.append("| Username | Type | Domain | Access Level | Valid |")
            lines.append("|----------|------|--------|-------------|-------|")
            for c in creds:
                lines.append(f"| {c['username']} | {c['secret_type']} | {c['domain']} " f"| {c['access_level']} | {'Yes' if c['valid'] else 'No'} |")
            lines.append("")

        # Attack Chains
        if chains:
            lines.append("## Attack Chains")
            lines.append("")
            lines.append("| Name | Score | Status | MITRE IDs |")
            lines.append("|------|-------|--------|-----------|")
            for c in chains:
                lines.append(f"| {c['name']} | {c['score']} | {c['status']} | {c.get('mitre_ids', '')} |")
            lines.append("")

        # Recent Activity
        lines.append("## Recent Activity")
        lines.append("")
        lines.append("| Time | Agent | Action | Summary |")
        lines.append("|------|-------|--------|---------|")
        for e in log[:20]:
            lines.append(f"| {e.get('created_at', '')} | {e.get('agent', '')} " f"| {e.get('action', '')} | {e.get('summary', '')} |")
        lines.append("")

        # Suggested Next Steps
        lines.append("## Suggested Next Steps")
        lines.append("")
        unconfirmed = [v for v in vulns if v.get("status") == "open"]
        if unconfirmed:
            lines.append(f"- **{len(unconfirmed)} unconfirmed vulns** — run PoC validation")
        open_creds = [c for c in creds if c.get("valid")]
        if open_creds:
            lines.append("- **Valid credentials available** — test for privilege escalation")
        incomplete_chains = [c for c in chains if c.get("status") in ("draft", "")]
        if incomplete_chains:
            lines.append("- **Incomplete attack chains** — continue chain development")
        if not unconfirmed and not open_creds and not incomplete_chains:
            lines.append("- All findings validated. Ready for report generation.")
        lines.append("")

        return "\n".join(lines)


# ── Shorthand ─────────────────────────────────────────────────────────────────


def get_default_db_path() -> Path:
    return Path(
        os.environ.get(
            "DST_FINDINGS_DB",
            str(Path(__file__).parent / "data" / "findings.db"),
        )
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
