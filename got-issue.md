# Dristi Pipeline Issues

Log issues encountered during automated hunting so they can be fixed later.
Write in this format:
```
## [YYYY-MM-DD HH:MM] Issue: Brief Description
- What happened:
- Impact:
- Suggested fix:
```

---

## [2026-06-14 10:09] Spoofy + cloud_enum: venv without pip
- **What happened:** Autopilot Phase 3 (INTEL/OSINT) failed to install Python deps for Spoofy and cloud_enum. Spoofy's `./venv/` exists but has no pip installed (`No module named pip`). cloud_enum has no `venv/` directory at all (`No such file or directory`).
- **Impact:** SPF/DMARC checking (Spoofy) and cloud bucket enumeration (cloud_enum) were blocked.
- **Root cause:** `scripts/tools/phase-intel.sh` `install_repo()` only created venvs on fresh clone; if repo existed (`.git/` check passed), no venv check was done. Spoofy's venv was created by `python3 -m venv` (without pip on Kali) instead of `uv venv`. cloud_enum was cloned but `install_repo()` skipped venv creation because it has `pyproject.toml` not `requirements.txt`.
- **Fix applied:**
  - `scripts/install.sh`: Added Phase 5d calling `phase-intel.sh --install`
  - `scripts/tools/phase-intel.sh`: Rewrote `install_repo()` to:
    - Always verify venv is healthy (even for existing repos) — recreates broken venvs
    - New `_setup_venv()` helper: detects/recreates broken venvs, handles both `requirements.txt` and `pyproject.toml` (cloud_enum)
  - Both venvs recreated and deps installed manually: Spoofy (16 packages), cloud_enum (7 packages)
