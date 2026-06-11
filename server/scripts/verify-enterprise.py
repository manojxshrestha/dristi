#!/usr/bin/env python3
"""Verify enterprise deployment readiness.

Checks:
1. All required modules load without errors
2. RBAC, state management, access control work
3. CRUD operations on findings DB
4. File system paths are writable
"""

import importlib
import sys
from pathlib import Path


def check(description: str, condition: bool, fix: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    symbol = "✓" if condition else "✗"
    print(f"  [{symbol}] {status}: {description}")
    if not condition and fix:
        print(f"       Fix: {fix}")
    return condition


def main() -> int:
    print("Dristi Enterprise Verification\n")
    print("─" * 50)

    # 1. Python version
    print("\n1. Python Environment")
    py_ok = check("Python >= 3.10", sys.version_info >= (3, 10))

    # 2. Module imports
    print("\n2. Module Imports")
    modules = [
        "server",
        "findings_db",
        "state_manager",
        "access_control",
        "task_tree",
        "knowledge_graph",
        "tool_parsers",
        "waf_evasion",
        "tool_verification",
    ]
    server_dir = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(server_dir))

    all_modules_ok = True
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
            check(f"import {mod_name}", True)
        except ImportError as e:
            check(f"import {mod_name}", False, str(e))
            all_modules_ok = False

    # 3. RBAC
    print("\n3. Role-Based Access Control")
    try:
        from access_control import (
            acquire_lock,
            check_access,
            get_access_grant,
            grant_access,
            release_lock,
            revoke_access,
            validate_role,
        )
        from access_control import (
            configure as ac_configure,
        )

        ac_configure(Path("/tmp/dristi-verify"))
        validate_role("admin")
        rbac_ok = check("validate_role() works", True)

        grant = grant_access("verify-eng", "tester", "operator", "editor")
        rbac_ok &= check("grant_access() works", grant["role"] == "operator")

        grant_read = get_access_grant("verify-eng", "tester")
        rbac_ok &= check("get_access_grant() works", grant_read is not None)

        access = check_access("verify-eng", "tester", required_level="guest")
        rbac_ok &= check("check_access() grants access", access["granted"] is True)

        revoke_access("verify-eng", "tester")
        grant_revoked = get_access_grant("verify-eng", "tester")
        rbac_ok &= check("revoke_access() works", grant_revoked is None)

        lock = acquire_lock("verify-eng", "tester", reason="verify", timeout=5)
        rbac_ok &= check("acquire_lock() works", lock["success"] is True)

        unlock = release_lock("verify-eng", "tester")
        rbac_ok &= check("release_lock() works", unlock["success"] is True)

    except Exception as e:
        check("RBAC tests", False, str(e))
        rbac_ok = False

    # 4. State Management
    print("\n4. State Management")
    try:
        from state_manager import configure as sm_configure
        from state_manager import create_checkpoint, list_checkpoints

        sm_configure(Path("/tmp/dristi-verify"))
        cp = create_checkpoint("verify-eng", "tester", "Verification checkpoint")
        sm_ok = check("create_checkpoint() works", "checkpoint_id" in cp)

        cps = list_checkpoints("verify-eng")
        sm_ok &= check("list_checkpoints() returns data", len(cps) >= 1)

    except Exception as e:
        check("State management tests", False, str(e))
        sm_ok = False

    # 5. Findings DB
    print("\n5. Findings Database")
    try:
        from findings_db import FindingsDB

        db = FindingsDB("/tmp/dristi-verify/findings.db")
        eng = db.init_engagement("verify-eng", "Verify Client", "web")
        db_ok = check("init_engagement() works", eng["status"] == "active")

        vuln = db.add_vuln("verify-eng", "Test Finding", "Low", 2.5, "https://test.com/")
        db_ok &= check("add_vuln() works", vuln["title"] == "Test Finding")

        vulns = db.list_vulns(engagement_id="verify-eng")
        db_ok &= check("list_vulns() works", len(vulns) == 1)

        updated = db.update_vuln(vuln["id"], severity="Medium")
        db_ok &= check("update_vuln() works", updated["severity"] == "Medium")

        cred = db.add_credential("verify-eng", "admin", "s3cret", secret_type="password")
        db_ok &= check("add_credential() works", cred["username"] == "admin")

        db.close()

    except Exception as e:
        check("Findings DB tests", False, str(e))
        db_ok = False

    # 6. Summary
    print("\n" + "─" * 50)
    all_pass = py_ok and all_modules_ok and rbac_ok and sm_ok and db_ok
    print(f"\n{'✓ ALL CHECKS PASSED' if all_pass else '✗ SOME CHECKS FAILED'}")
    print(f"  Python:          {'PASS' if py_ok else 'FAIL'}")
    print(f"  Module imports:  {'PASS' if all_modules_ok else 'FAIL'}")
    print(f"  RBAC:            {'PASS' if rbac_ok else 'FAIL'}")
    print(f"  State mgmt:      {'PASS' if sm_ok else 'FAIL'}")
    print(f"  Findings DB:     {'PASS' if db_ok else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
