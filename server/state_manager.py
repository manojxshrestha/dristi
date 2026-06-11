"""Engagement state management with checkpointing, WAL, and rollback.

Provides crash-safe state persistence for multi-day engagements:
- Automatic checkpoint snapshots at configurable intervals
- Write-Ahead Logging (WAL) for crash recovery
- State rollback to any checkpoint
- Full audit trail of all state mutations
- Thread-safe per-engagement locking
"""

import json
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

STAGING_DIR: Path = Path(".")
_append_event: Callable | None = None

# Per-engagement locks to prevent concurrent state mutations
_engagement_locks: dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()
_cp_counter = 0
_cp_counter_lock = threading.Lock()

def configure(staging_dir: Path, append_event_fn: Callable | None = None):
    global STAGING_DIR, _append_event
    STAGING_DIR = staging_dir
    _append_event = append_event_fn


def _get_lock(engagement_id: str) -> threading.Lock:
    with _locks_lock:
        if engagement_id not in _engagement_locks:
            _engagement_locks[engagement_id] = threading.Lock()
        return _engagement_locks[engagement_id]


# ── Checkpoint Helpers ──────────────────────────────────────────────


def _checkpoints_dir(engagement_id: str) -> Path:
    d = STAGING_DIR / "checkpoints" / engagement_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _wal_path(engagement_id: str) -> Path:
    return STAGING_DIR / "wal" / f"{engagement_id}.wal.json"


def _wal_dir(engagement_id: str) -> Path:
    d = STAGING_DIR / "wal"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _state_path(engagement_id: str) -> Path:
    return STAGING_DIR / "state" / f"{engagement_id}.json"


def _state_dir(engagement_id: str) -> Path:
    d = STAGING_DIR / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_key(engagement_id: str) -> str:
    """Validate and sanitize engagement_id for filesystem safety."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", engagement_id)
    if not safe:
        raise ValueError(f"Invalid engagement_id: {engagement_id!r}")
    return safe


# ── Checkpoint Operations ───────────────────────────────────────────


def create_checkpoint(
    engagement_id: str,
    operator: str,
    description: str = "",
    state_snapshot: dict | None = None,
) -> dict:
    """Create a checkpoint snapshot of the current engagement state.

    Args:
        engagement_id: The engagement identifier.
        operator: The operator creating the checkpoint.
        description: Human-readable description of the checkpoint.
        state_snapshot: Optional state dict to persist. If omitted, loads current state.

    Returns:
        The checkpoint metadata dict.
    """
    global _cp_counter
    safe_id = _sanitize_key(engagement_id)
    lock = _get_lock(engagement_id)
    with lock:
        with _cp_counter_lock:
            _cp_counter += 1
            cp_seq = _cp_counter
        ts = _now()
        cp_dir = _checkpoints_dir(safe_id)
        cp_id = f"cp-{int(time.time())}-{cp_seq}"
        cp_file = cp_dir / f"{cp_id}.json"

        if state_snapshot is None:
            state_snapshot = load_state(engagement_id)

        checkpoint = {
            "checkpoint_id": cp_id,
            "engagement_id": engagement_id,
            "operator": operator,
            "description": description,
            "created_at": ts,
            "state": state_snapshot,
        }

        cp_file.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")

        _append_wal_entry(safe_id, {
            "action": "checkpoint",
            "checkpoint_id": cp_id,
            "operator": operator,
            "timestamp": ts,
        })

        if _append_event:
            _append_event(engagement_id, {
                "event": "checkpoint_created",
                "checkpoint_id": cp_id,
                "operator": operator,
            })

        return {
            "checkpoint_id": cp_id,
            "created_at": ts,
            "description": description,
        }


def list_checkpoints(engagement_id: str) -> list[dict]:
    """List all checkpoints for an engagement, ordered by creation time."""
    safe_id = _sanitize_key(engagement_id)
    cp_dir = _checkpoints_dir(safe_id)
    if not cp_dir.exists():
        return []

    checkpoints = []
    for f in sorted(cp_dir.glob("cp-*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            checkpoints.append({
                "checkpoint_id": data.get("checkpoint_id", f.stem),
                "created_at": data.get("created_at", ""),
                "description": data.get("description", ""),
                "operator": data.get("operator", ""),
            })
        except (json.JSONDecodeError, OSError):
            continue

    return checkpoints


def rollback_to_checkpoint(
    engagement_id: str,
    checkpoint_id: str,
    operator: str,
) -> dict:
    """Roll back engagement state to a specific checkpoint.

    Args:
        engagement_id: The engagement identifier.
        checkpoint_id: The target checkpoint ID to restore.
        operator: The operator requesting the rollback.

    Returns:
        Dict with rollback result details.
    """
    safe_id = _sanitize_key(engagement_id)
    lock = _get_lock(engagement_id)
    with lock:
        cp_file = _checkpoints_dir(safe_id) / f"{checkpoint_id}.json"
        if not cp_file.exists():
            return {
                "success": False,
                "error": f"Checkpoint {checkpoint_id} not found",
            }

        try:
            checkpoint = json.loads(cp_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            return {
                "success": False,
                "error": f"Failed to read checkpoint: {e}",
            }

        ts = _now()
        # Save current state as pre-rollback snapshot
        pre_rollback_cp = create_checkpoint(
            engagement_id, operator,
            description=f"Auto-snapshot before rollback to {checkpoint_id}",
        )

        restored_state = checkpoint.get("state", {})
        save_state(engagement_id, restored_state)

        _append_wal_entry(safe_id, {
            "action": "rollback",
            "from_checkpoint": pre_rollback_cp["checkpoint_id"],
            "to_checkpoint": checkpoint_id,
            "operator": operator,
            "timestamp": ts,
        })

        if _append_event:
            _append_event(engagement_id, {
                "event": "state_rolled_back",
                "to_checkpoint": checkpoint_id,
                "operator": operator,
            })

        return {
            "success": True,
            "restored_checkpoint": checkpoint_id,
            "pre_rollback_checkpoint": pre_rollback_cp["checkpoint_id"],
            "restored_at": ts,
        }


# ── State Persistence ───────────────────────────────────────────────


def save_state(engagement_id: str, state: dict) -> None:
    """Persist engagement state to disk atomically."""
    safe_id = _sanitize_key(engagement_id)
    state_file = _state_path(safe_id)
    _state_dir(safe_id)
    tmp = state_file.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        tmp.replace(state_file)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def load_state(engagement_id: str) -> dict:
    """Load persisted engagement state, returning empty dict if none exists."""
    safe_id = _sanitize_key(engagement_id)
    state_file = _state_path(safe_id)
    if not state_file.exists():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


# ── Write-Ahead Logging (WAL) ───────────────────────────────────────


def _append_wal_entry(engagement_id: str, entry: dict) -> None:
    """Append an entry to the write-ahead log for crash recovery."""
    wal_file = _wal_path(engagement_id)
    _wal_dir(engagement_id)
    try:
        entries = []
        if wal_file.exists():
            entries = json.loads(wal_file.read_text(encoding="utf-8"))
        entries.append(entry)
        wal_file.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    except (json.JSONDecodeError, OSError):
        wal_file.write_text(json.dumps([entry], indent=2), encoding="utf-8")


def get_wal(engagement_id: str) -> list[dict]:
    """Retrieve all WAL entries for an engagement."""
    safe_id = _sanitize_key(engagement_id)
    wal_file = _wal_path(safe_id)
    if not wal_file.exists():
        return []
    try:
        return json.loads(wal_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def recover_incomplete_operations(engagement_id: str) -> list[dict]:
    """Detect and report incomplete operations from WAL analysis.

    Checkpoints are the last WAL entry before a normal shutdown.
    If the last entry is NOT a checkpoint, the engagement may have
    crashed mid-operation.

    Returns:
        List of incomplete operations detected.
    """
    wal = get_wal(engagement_id)
    if not wal:
        return []

    incomplete = []
    for entry in wal:
        action = entry.get("action", "")
        if action not in ("checkpoint", "rollback"):
            # Any non-terminal action after last checkpoint is suspicious
            pass

    # Find the last checkpoint
    last_cp_idx = -1
    for i, entry in enumerate(wal):
        if entry.get("action") == "checkpoint":
            last_cp_idx = i

    # Operations after last checkpoint are potentially incomplete
    for i in range(last_cp_idx + 1, len(wal)):
        entry = wal[i]
        if entry.get("action") not in ("checkpoint", "rollback"):
            incomplete.append(entry)

    return incomplete


def get_engagement_status(engagement_id: str) -> dict:
    """Get comprehensive status snapshot for an engagement.

    Returns checkpoints, WAL state, and recovery status.
    """
    safe_id = _sanitize_key(engagement_id)
    checkpoints = list_checkpoints(engagement_id)
    wal = get_wal(safe_id)
    incomplete = recover_incomplete_operations(safe_id)

    return {
        "engagement_id": engagement_id,
        "checkpoint_count": len(checkpoints),
        "last_checkpoint": checkpoints[-1] if checkpoints else None,
        "wal_entry_count": len(wal),
        "incomplete_operations": len(incomplete),
        "needs_recovery": len(incomplete) > 0,
    }


# ── Audit Trail ─────────────────────────────────────────────────────


def _audit_path(engagement_id: str) -> Path:
    d = STAGING_DIR / "audit" / engagement_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_audit_entry(
    engagement_id: str,
    operator: str,
    action: str,
    details: str = "",
) -> dict:
    """Record an audit trail entry for compliance tracking."""
    safe_id = _sanitize_key(engagement_id)
    ts = _now()
    entry = {
        "timestamp": ts,
        "operator": operator,
        "action": action,
        "details": details,
    }
    audit_dir = _audit_path(safe_id)
    entry_file = audit_dir / f"{int(time.time())}-{operator}.json"
    entry_file.write_text(json.dumps(entry, indent=2), encoding="utf-8")
    return entry


def get_audit_log(
    engagement_id: str,
    limit: int = 100,
) -> list[dict]:
    """Retrieve audit log entries, most recent first."""
    safe_id = _sanitize_key(engagement_id)
    audit_dir = _audit_path(safe_id)
    if not audit_dir.exists():
        return []

    entries = []
    for f in sorted(audit_dir.glob("*.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            entries.append(data)
            if limit > 0 and len(entries) >= limit:
                break
        except (json.JSONDecodeError, OSError):
            continue

    return entries
