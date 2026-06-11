"""Role-based access control for multi-user engagement management.

Provides:
- 5-tier RBAC (ADMIN > OPERATOR > ANALYST > AUDITOR > SERVICE_ACCOUNT)
- Per-engagement access grants with expiration
- Pessimistic locking for exclusive engagement access
- Optimistic concurrency via version tokens
- Session tracking and audit logging
"""

import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Constants ───────────────────────────────────────────────────────

RBAC_ROLES = ["service_account", "auditor", "analyst", "operator", "admin"]
RBAC_HIERARCHY = {role: i for i, role in enumerate(RBAC_ROLES)}

ACCESS_LEVELS = {
    "owner": 4,
    "editor": 3,
    "reviewer": 2,
    "guest": 1,
    "none": 0,
}

ACCESS_DIR: Path = Path(".")

# ── Data Structures ─────────────────────────────────────────────────


class _EngagementLock:
    """Represents an exclusive lock on an engagement."""

    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.lock = threading.Lock()
        self.holder: str | None = None
        self.reason: str = ""
        self.acquired_at: str | None = None
        self.expires_at: float | None = None
        self.version: int = 0


# In-memory lock registry
_engagement_locks: dict[str, _EngagementLock] = {}
_locks_lock = threading.Lock()
_token_counter = 0
_token_lock = threading.Lock()


# ── Path Helpers ────────────────────────────────────────────────────


def _grants_path() -> Path:
    d = ACCESS_DIR / "access_grants"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sessions_path() -> Path:
    d = ACCESS_DIR / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _audit_path() -> Path:
    d = ACCESS_DIR / "audit"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sanitize_key(key: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", key)
    if not safe:
        raise ValueError(f"Invalid identifier: {key!r}")
    return safe


# ── Configuration ───────────────────────────────────────────────────


def configure(access_dir: Path):
    """Called by server.py to inject the access control data directory."""
    global ACCESS_DIR
    ACCESS_DIR = access_dir


# ── Role Validation ─────────────────────────────────────────────────


def validate_role(role: str) -> str:
    """Validate and normalize a role string."""
    role = role.lower().strip()
    if role not in RBAC_ROLES:
        raise ValueError(
            f"Invalid role {role!r}. Must be one of: {', '.join(RBAC_ROLES)}"
        )
    return role


def validate_access_level(level: str) -> str:
    """Validate and normalize an access level string."""
    level = level.lower().strip()
    if level not in ACCESS_LEVELS:
        raise ValueError(
            f"Invalid access level {level!r}. Must be one of: {', '.join(ACCESS_LEVELS)}"
        )
    return level


def role_has_at_least(role: str, minimum_role: str) -> bool:
    """Check if a role meets or exceeds a minimum role threshold."""
    return RBAC_HIERARCHY.get(role, -1) >= RBAC_HIERARCHY.get(minimum_role, 999)


# ── Access Grant Management ─────────────────────────────────────────


def grant_access(
    engagement_id: str,
    operator: str,
    role: str,
    access_level: str = "editor",
    expires_in_days: int = 30,
) -> dict:
    """Grant an operator access to an engagement.

    Args:
        engagement_id: The engagement to grant access to.
        operator: The operator identifier.
        role: RBAC role (admin, operator, analyst, auditor, service_account).
        access_level: Access level (owner, editor, reviewer, guest).
        expires_in_days: Number of days until the grant expires.

    Returns:
        The access grant record.
    """
    safe_eid = _sanitize_key(engagement_id)
    safe_op = _sanitize_key(operator)
    role = validate_role(role)
    access_level = validate_access_level(access_level)

    grant = {
        "engagement_id": engagement_id,
        "operator": operator,
        "role": role,
        "access_level": access_level,
        "granted_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat(),
        "revoked": False,
    }

    grant_file = _grants_path() / f"{safe_eid}_{safe_op}.json"
    grant_file.write_text(json.dumps(grant, indent=2), encoding="utf-8")
    return grant


def revoke_access(engagement_id: str, operator: str) -> dict:
    """Revoke an operator's access to an engagement.

    Args:
        engagement_id: The engagement identifier.
        operator: The operator to revoke.

    Returns:
        The updated grant record.
    """
    safe_eid = _sanitize_key(engagement_id)
    safe_op = _sanitize_key(operator)
    grant_file = _grants_path() / f"{safe_eid}_{safe_op}.json"

    if not grant_file.exists():
        return {"success": False, "error": "Grant not found"}

    grant = json.loads(grant_file.read_text(encoding="utf-8"))
    grant["revoked"] = True
    grant_file.write_text(json.dumps(grant, indent=2), encoding="utf-8")
    return {"success": True, "operator": operator}


def get_access_grant(engagement_id: str, operator: str) -> dict | None:
    """Retrieve an operator's access grant for an engagement."""
    safe_eid = _sanitize_key(engagement_id)
    safe_op = _sanitize_key(operator)
    grant_file = _grants_path() / f"{safe_eid}_{safe_op}.json"

    if not grant_file.exists():
        return None

    try:
        grant = json.loads(grant_file.read_text(encoding="utf-8"))

        # Check expiration
        expires_at = grant.get("expires_at", "")
        if expires_at:
            try:
                exp = datetime.fromisoformat(expires_at)
                if exp < datetime.now(timezone.utc):
                    return None
            except (ValueError, TypeError):
                pass

        # Check revocation
        if grant.get("revoked", False):
            return None

        return grant
    except (json.JSONDecodeError, OSError):
        return None


def list_access_grants(engagement_id: str) -> list[dict]:
    """List all active access grants for an engagement."""
    safe_eid = _sanitize_key(engagement_id)
    grants_dir = _grants_path()
    if not grants_dir.exists():
        return []

    grants = []
    for f in grants_dir.glob(f"{safe_eid}_*.json"):
        try:
            grant = get_access_grant(engagement_id, f.stem.replace(f"{safe_eid}_", ""))
            if grant:
                grants.append(grant)
        except ValueError:
            continue

    return grants


# ── Pessimistic Locking ─────────────────────────────────────────────


def acquire_lock(
    engagement_id: str,
    operator: str,
    reason: str = "",
    timeout: int = 300,
) -> dict:
    """Acquire an exclusive lock on an engagement.

    Prevents concurrent modifications during sensitive phases.

    Args:
        engagement_id: The engagement to lock.
        operator: The operator requesting the lock.
        reason: Why the lock is needed.
        timeout: Lock timeout in seconds (default 300).

    Returns:
        Lock result dict with success status and lock version.
    """
    with _locks_lock:
        if engagement_id not in _engagement_locks:
            _engagement_locks[engagement_id] = _EngagementLock(engagement_id)
        eng_lock = _engagement_locks[engagement_id]

    acquired = eng_lock.lock.acquire(timeout=timeout)
    if not acquired:
        return {
            "success": False,
            "error": f"Could not acquire lock within {timeout}s timeout",
        }

    eng_lock.holder = operator
    eng_lock.reason = reason
    eng_lock.acquired_at = datetime.now(timezone.utc).isoformat()
    eng_lock.expires_at = time.time() + timeout
    eng_lock.version += 1

    _log_access_event(engagement_id, operator, "lock_acquired", reason)

    return {
        "success": True,
        "holder": operator,
        "reason": reason,
        "version": eng_lock.version,
        "acquired_at": eng_lock.acquired_at,
    }


def release_lock(engagement_id: str, operator: str) -> dict:
    """Release an exclusive lock on an engagement.

    Args:
        engagement_id: The engagement to unlock.
        operator: The operator releasing the lock.

    Returns:
        Release result dict.
    """
    with _locks_lock:
        eng_lock = _engagement_locks.get(engagement_id)

    if not eng_lock:
        return {"success": False, "error": "No lock found for this engagement"}

    if eng_lock.holder != operator:
        return {
            "success": False,
            "error": f"Lock held by {eng_lock.holder}, not {operator}",
        }

    eng_lock.holder = None
    eng_lock.reason = ""
    eng_lock.acquired_at = None
    eng_lock.lock.release()

    _log_access_event(engagement_id, operator, "lock_released", "")

    return {"success": True}


def get_lock_status(engagement_id: str) -> dict:
    """Get the current lock status for an engagement without acquiring."""
    with _locks_lock:
        eng_lock = _engagement_locks.get(engagement_id)

    if not eng_lock:
        return {"locked": False}

    return {
        "locked": eng_lock.holder is not None,
        "holder": eng_lock.holder,
        "reason": eng_lock.reason,
        "acquired_at": eng_lock.acquired_at,
        "version": eng_lock.version,
    }


# ── Optimistic Concurrency ──────────────────────────────────────────


def get_version_token(engagement_id: str) -> dict:
    """Get the current version token for optimistic concurrency control.

    Used for non-blocking reads where the caller checks the version
    before writing to detect conflicts.
    """
    with _locks_lock:
        eng_lock = _engagement_locks.get(engagement_id)

    if not eng_lock:
        return {"engagement_id": engagement_id, "version": 0}

    return {
        "engagement_id": engagement_id,
        "version": eng_lock.version,
        "holder": eng_lock.holder,
    }


# ── Session Tracking ────────────────────────────────────────────────


def create_session(
    engagement_id: str,
    operator: str,
    session_type: str = "interactive",
) -> dict:
    """Create a new operator session for an engagement.

    Args:
        engagement_id: The engagement identifier.
        operator: The operator starting the session.
        session_type: Type of session (interactive, automated, api).

    Returns:
        Session record dict.
    """
    safe_eid = _sanitize_key(engagement_id)
    safe_op = _sanitize_key(operator)
    with _token_lock:
        global _token_counter
        _token_counter += 1
        session_id = f"ses-{int(time.time() * 1000)}-{_token_counter}-{safe_op}"

    session = {
        "session_id": session_id,
        "engagement_id": engagement_id,
        "operator": operator,
        "session_type": session_type,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "last_active": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }

    session_file = _sessions_path() / f"{safe_eid}_{session_id}.json"
    session_file.write_text(json.dumps(session, indent=2), encoding="utf-8")

    _log_access_event(engagement_id, operator, "session_started", session_type)
    return session


def end_session(engagement_id: str, session_id: str) -> dict:
    """End an operator session."""
    safe_eid = _sanitize_key(engagement_id)
    session_file = _sessions_path() / f"{safe_eid}_{session_id}.json"

    if not session_file.exists():
        return {"success": False, "error": "Session not found"}

    try:
        session = json.loads(session_file.read_text(encoding="utf-8"))
        session["active"] = False
        session["ended_at"] = datetime.now(timezone.utc).isoformat()
        session_file.write_text(json.dumps(session, indent=2), encoding="utf-8")

        _log_access_event(
            engagement_id, session.get("operator", ""), "session_ended", session_id
        )
        return {"success": True, "session_id": session_id}
    except (json.JSONDecodeError, OSError) as e:
        return {"success": False, "error": str(e)}


def get_active_sessions(engagement_id: str) -> list[dict]:
    """Get all active sessions for an engagement."""
    safe_eid = _sanitize_key(engagement_id)
    sessions_dir = _sessions_path()
    if not sessions_dir.exists():
        return []

    active = []
    for f in sessions_dir.glob(f"{safe_eid}_*.json"):
        try:
            session = json.loads(f.read_text(encoding="utf-8"))
            if session.get("active", False):
                active.append(session)
        except (json.JSONDecodeError, OSError):
            continue

    return active


# ── Audit Logging ───────────────────────────────────────────────────


def _log_access_event(
    engagement_id: str,
    operator: str,
    action: str,
    details: str = "",
) -> None:
    """Log an access control event to the audit trail."""
    audit_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engagement_id": engagement_id,
        "operator": operator,
        "action": action,
        "details": details,
    }
    safe_eid = _sanitize_key(engagement_id)
    audit_dir = _audit_path()
    log_file = audit_dir / f"{safe_eid}_access.log"

    try:
        entries = []
        if log_file.exists():
            entries = json.loads(log_file.read_text(encoding="utf-8"))
        entries.append(audit_entry)
        # Keep last 1000 entries
        if len(entries) > 1000:
            entries = entries[-1000:]
        log_file.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    except (json.JSONDecodeError, OSError):
        log_file.write_text(json.dumps([audit_entry], indent=2), encoding="utf-8")


def get_access_log(
    engagement_id: str,
    limit: int = 100,
) -> list[dict]:
    """Retrieve access audit log entries."""
    safe_eid = _sanitize_key(engagement_id)
    log_file = _audit_path() / f"{safe_eid}_access.log"
    if not log_file.exists():
        return []

    try:
        entries = json.loads(log_file.read_text(encoding="utf-8"))
        return entries[-limit:]
    except (json.JSONDecodeError, OSError):
        return []


# ── Resource-Based Access Check ─────────────────────────────────────


def check_access(
    engagement_id: str,
    operator: str,
    required_level: str = "guest",
) -> dict:
    """Check whether an operator has sufficient access to an engagement.

    Args:
        engagement_id: The engagement identifier.
        operator: The operator requesting access.
        required_level: Minimum access level required.

    Returns:
        Dict with granted (bool) and operator role/level info.
    """
    grant = get_access_grant(engagement_id, operator)
    if not grant:
        return {
            "granted": False,
            "reason": "No active access grant",
            "operator": operator,
        }

    required = ACCESS_LEVELS.get(required_level, 0)
    actual = ACCESS_LEVELS.get(grant.get("access_level", "none"), 0)

    if actual < required:
        return {
            "granted": False,
            "reason": (
                f"Access level '{grant.get('access_level')}' insufficient "
                f"(need '{required_level}')"
            ),
            "operator": operator,
            "role": grant.get("role"),
            "access_level": grant.get("access_level"),
        }

    return {
        "granted": True,
        "operator": operator,
        "role": grant.get("role"),
        "access_level": grant.get("access_level"),
    }
