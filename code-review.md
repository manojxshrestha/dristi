# Dristi Project — Comprehensive Code Review

**Generated:** 2026-06-12
**Reviewer:** OpenCode (senior security engineer + Python architect)
**Scope:** 675 directories, 3701 files, ~13K lines server Python, ~28K lines agent .md files

---

## Table of Contents

1. [Architecture & Modularity](#1-architecture--modularity)
2. [Python Code Quality](#2-python-code-quality)
3. [Agent Files (83 .md files)](#3-agent-files)
4. [Knowledge & Data Files](#4-knowledge--data-files)
5. [Scripts](#5-scripts)
6. [Testing](#6-testing)
7. [Configuration & Security](#7-configuration--security)
8. [Documentation](#8-documentation)
9. [Ranked Action Plan](#9-ranked-action-plan)

---

## 1. Architecture & Modularity

### 1.1 server.py Monolith (6,444 lines)

**Issue:** `server/server.py` is 6,444 lines with 89 `@mcp.tool()` definitions. This is a textbook god module. Every new tool must be added here, making merge conflicts likely and discoverability poor.

**Impact:** Maintainability — any developer adding a tool must navigate 6K+ lines. The file mixes I/O, business logic, formatting, logging, and security sanitization.

**Recommendation:** Split into domain modules:
- `tools/wstg_tools.py` — `get_wstg_test`, `search_wstg`, `get_test_payloads`, `get_technique_guide`
- `tools/findings_tools.py` — `log_finding`, `get_findings`, all findings_* wrappers
- `tools/engagement_tools.py` — scope, config, checkpoint, deliverable tools
- `tools/report_tools.py` — `generate_report`, `get_coverage`, `get_tool_coverage`
- Keep a thin `server.py` that imports and registers from submodules

**Severity:** Medium — not a bug, but growing tech debt.
**Effort:** Medium (2-3hr to split, +testing)

### 1.2 Dependency Injection Pattern (`configure()`)

**Issue:** Seven modules (`waf_evasion.py`, `knowledge_graph.py`, `endpoint_priority.py`, `context_compression.py`, `task_tree.py`, `tool_verification.py`, `state_manager.py`, `access_control.py`) use a global `configure()` pattern that mutates module-level globals after import. Example (`waf_evasion.py:14-17`):
```python
DATA_DIR: Path = Path(".")
_atomic_write_json = None
_append_event = None
```

**Impact:** Fragile — configure() must be called before any function, but nothing enforces this. If server.py crashes during init, modules have stale defaults (`Path(".")` = CWD). Not thread-safe for module-level globals.

**Recommendation:** Use a proper DI container or pass dependencies explicitly as function parameters. At minimum, add asserts and `_configured` flags to each function:
```python
_configured = False
def configure(...):
    global _configured
    _configured = True

def _require_configured():
    if not _configured:
        raise RuntimeError("configure() not called")
```

**Severity:** Medium — risk of silent misconfiguration.
**Effort:** Medium (2hr to add guards + hardening)

### 1.3 RBAC + WAL State Management (Over-engineering?)

**Issue:** `access_control.py` (529 lines) implements 5-tier RBAC with per-engagement locks, expiration, session tracking, and audit logging. `state_manager.py` (418 lines) implements WAL checkpointing with crash recovery. Both are designed for multi-user enterprise deployments but the project is a single-user CLI tool.

**Impact:** ~950 lines of dead-adjacent code. `access_control.py` is never imported by `server.py` — it is only tested in isolation. The `grant_access`, `acquire_lock`, and `create_session` functions are never exposed as MCP tools. The WAL/journaling in `state_manager.py` duplicates what SQLite provides natively in `findings_db.py`.

**Recommendation:** Either:
- (a) Expose access_control tools via MCP if multi-user is planned, or
- (b) Remove both modules and use simple file-based locking + SQLite transactions
- At minimum, document these as "roadmap infrastructure" so readers don't assume dead code

**Severity:** Medium — 950 lines of dead/unreachable code.
**Effort:** Small (document) to Large (remove + refactor)

### 1.4 Cryptography (`crypto_utils.py`)

**Issue:** `crypto_utils.py:54-61` — encryption is optional (`HAS_CRYPTO` flag). When the `cryptography` package is not installed (exceptionally common on fresh installs), credentials are stored **in plaintext** with a silent fallback:
```python
def decrypt_secret(ciphertext: str) -> str:
    if not HAS_CRYPTO or not ciphertext:
        return ciphertext
```
The key file at `server/data/encryption.key` is auto-generated on first use with `chmod 0o600`.

**Impact:** If `cryptography` is missing (e.g., `pip install dristi-server` without `[encrypt]` extra), all credentials in the SQLite DB are plaintext. The `[encrypt]` extra in `pyproject.toml:22` is empty — there is no `encrypt` extra defined (the `cryptography` dependency is in `[project]`, not `[project.optional-dependencies]`).

**Recommendation:**
- Make `cryptography` a hard dependency (move it from optional to required, or define `[encrypt]` properly)
- Add a loud warning on startup if `HAS_CRYPTO` is False
- Validate key integrity on startup with a known-answer test

**Severity:** High — credential exposure risk when deps are missing.
**Effort:** Small (<30min)

### 1.5 Module Interaction Summary

The 13 server modules interact through:
- `server.py` importing and re-exporting their public functions
- `configure()` calls for shared state injection
- Filesystem pass-through via `DATA_DIR` / `STAGING_DIR`
- SQLite via `findings_db.py` (called from inline wrappers in server.py)

This is functional but tightly coupled. A service layer or explicit protocol between modules would improve testability.

---

## 2. Python Code Quality

### 2.1 Type Hints — Mypy

**Current state:** 8 errors found in 2 files (server.py + scripts/tools/scope_table_parser.py). The `pyproject.toml` disables 8 error categories including `import-untyped`, `no-untyped-def`, and `attr-defined`.

**Real issues:**
- `server/server.py:4740,4742` — `Unsupported operand types for < ("int" and "object")` — comparing int to object, likely a dict value of ambiguous type
- `server/server.py:4817` — missing type annotation for `seen_pairs`
- `scripts/tools/scope_table_parser.py:171,259` — missing type annotations for `cols`, `merged`
- `scripts/tools/scope_table_parser.py:512-513` — assigning `float` to `str` typed variables

**Impact:** Low for runtime (Python ignores types), but the 8 disabled error categories mean ~29 total issues if enabled. Missing annotations make IDE assistance poor.

**Recommendation:** Enable `no-untyped-def` in `pyproject.toml:37` and annotate return types. Fix the 8 real errors. Add `# type: ignore[override]` where intentional.

**Severity:** Low — correctness impact minimal.
**Effort:** Medium (1-2hr to add types across server.py)

### 2.2 Error Handling — `except Exception:` Patterns

**Issue:** `server/server.py` has 16 bare `except Exception:` blocks (lines 269, 382, 398, 541, 1725, 3387, 3393, 3399, 4044, 4159, 4421, 5950, 5983, 6195, 6334, 6426). Of these, 4 swallow exceptions silently:
- `server.py:398` — `pass  # nosec B110` — logging error swallowed
- `server.py:4159` — `pass  # nosec B110` — unknown
- `server.py:5983` — `pass  # nosec B110` — status re-run error swallowed
- `crypto_utils.py:60` — `pass  # nosec B110` — decryption failure returns plaintext

**Impact:** Silent failures make debugging hard. The crypto_utils one is the most dangerous — if decryption fails, plaintext is returned silently (see 1.4).

**Recommendation:**
- Log all swallowed exceptions at minimum: `logger.warning("...", exc_info=True)`
- For crypto: raise on decryption failure instead of returning plaintext
- For logging: acceptable to swallow, but log the error

**Severity:** Medium — silent crypto failures are High.
**Effort:** Small (30min to add logging to all 16 blocks)

### 2.3 Shell Injection — `subprocess` calls

**Issue:** Two `shell=True` calls in `server/server.py`:
- `server.py:5923-5928` — `validate_poc` function passes user-supplied `command` directly to `shell=True` with full shell interpretation
- `server.py:5975-5979` — same function, second `shell=True` call

The `_validate_shell_arg()` function at `server.py:6230` only checks for shell metacharacters but is NOT used in `validate_poc`. It IS used in `burp_send_request` (`server.py:6406`).

**Impact:** If an MCP client sends a crafted command to `validate_poc`, arbitrary shell commands can be executed. E.g., `curl -s http://target.com; rm -rf /` would execute both commands. While this is a pentesting tool and the MCP client is the LLM, a compromised LLM prompt could inject commands.

**Recommendation:**
- Use `shlex.split()` to parse the command safely before passing to `subprocess.run()` with `shell=False`
- Or add `_validate_shell_arg()` validation to the `command` parameter
- At minimum, log a warning: "Executing potentially unsafe shell command"

The other `subprocess.run()` calls at lines 5285-5370 (git_checkpoint, git_rollback) use `shell=False` with hardcoded argument lists — these are safe.

**Severity:** High — shell injection in production code.
**Effort:** Small (<30min to add shlex.split or validation)

### 2.4 Bandit Issues Analysis

**.bandit config** skips 27+ categories including B602 (`shell=True`), B603 (subprocess w/o shell), B404 (subprocess import), B110 (bare except), B310 (urllib.urlopen). The pentest tool justification is valid for most.

**File-by-file analysis:**

| File | Reported | Real Issues |
|------|----------|-------------|
| `server/server.py` | 0 bandit issues (27 skipped) | 2 `shell=True` calls are real (2.3 above) |
| `scripts/bughunt.py` | 8 findings (2 Medium, 6 Low) | 2 B310 `urllib.urlopen` Medium — no scheme restriction, could open `file://` URLs |
| `server/waf_evasion.py` | 0 | Clean |
| `server/crypto_utils.py` | 0 | B110 bare except at line 60 is real (see 2.2) |

**Bandit gaps:** The `.bandit` skip list is overly broad. B310 (urllib.urlopen) should NOT be skipped globally — `bughunt.py` uses it without scheme validation:
```python
# bughunt.py:121
urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1)
```

**Recommendation:** Remove B310 from global skips. Narrow the skip list to project-relevant categories only.

**Severity:** Low-Medium — theoretical risk in pentest context.
**Effort:** Small (15min to narrow .bandit)

### 2.5 eval()/exec()/pickle.loads()/__import__()

**No usage found in server/ or scripts/ code.** All matches in the repo are from third-party libraries (pydantic, pygments, yaml, cffi, etc.). This is clean.

**One note:** `yaml.safe_load()` is used at `server.py:218` — correct choice. The YAML constructor from `pyyaml` could potentially `__import__` arbitrary modules, but `safe_load` prevents this.

### 2.6 Threading — Lock Correctness

**`state_manager.py`:** Uses `_get_lock()` which creates per-engagement locks protected by `_locks_lock`. This is correct for the double-checked locking pattern. No deadlock risk — locks are acquired one at a time with `with lock:`.

**`access_control.py`:** Same pattern — `_engagement_locks` dict protected by `_locks_lock`. The `acquire_lock` function at line 235 uses `lock.acquire(timeout=timeout)` with a timeout, preventing deadlock.

**`findings_db.py`:** Uses `threading.local()` for SQLite connections. This is the correct pattern for SQLite thread safety. However, the `_init_schema()` method is called from `__init__`, which may run on a different thread than subsequent operations — the schema should be initialized per-connection.

**Impact:** The thread-local SQLite connection pattern has a subtle bug: schema init happens once in `__init__`, but the actual connection is created lazily per-thread. If a new thread calls any DB method, the schema won't be initialized for that connection.

**Recommendation:** Move schema initialization into the per-thread connection getter at `findings_db.py`:
```python
def _get_conn(self) -> sqlite3.Connection:
    if not hasattr(self._local, "conn") or self._local.conn is None:
        self._local.conn = sqlite3.connect(str(self.db_path))
        self._init_schema(self._local.conn)
    return self._local.conn
```

**Severity:** Low — only affects multi-threaded access, which rarely happens in a single-user CLI.
**Effort:** Small (15min fix)

### 2.7 JSON Loading Safety

All `json.load()` calls in server.py use `json.loads()` on trusted local files or controlled inputs. The `json.load()` variant (from file handles) is not used in server.py. No safety issues — all JSON sources are server files, not user uploads.

---

## 3. Agent Files (83 .md files)

### 3.1 Size Distribution (28,104 lines total)

| Range | Count | Files |
|-------|-------|-------|
| >1000 lines | 3 | `bug-bounty.md` (2,236), `osint-methodology.md` (1,674), `web2-vuln-classes.md` (852) |
| 400-1000 lines | 19 | `exploit.md`, `web2-recon.md`, `hunt-ssrf.md`, `report-writing.md`, `cloud-iam-deep.md`, etc. |
| 200-400 lines | 28 | `hunt-xss.md` (441), `hunt-sqli.md` (438), etc. |
| 100-200 lines | 16 | `hunt-mfa-bypass.md`, `hunt-crlf.md`, etc. |
| 50-100 lines | 10 | `hunt-clickjacking.md`, `capture.md`, etc. |
| <50 lines | 7 | `scope.md` (20), `report.md` (34), `validate.md` (64), etc. |

### 3.2 Thin Agents — Not Useful

**`scope.md`** (20 lines) — Contains only a checklist of questions to ask the user. No actual MCP tool calls, no error handling guidance, no edge cases. The instructions say "call register_scope()" but don't explain how to handle partial scope tables, malformed domains, or retries.

**`report.md`** (34 lines) — Just says "call generate_report()". No guidance on report customization, evidence organization, or finding severity justification.

**`capture.md`** (79 lines) — Minimal. Says "collect screenshots and HAR files" but gives no technical guidance on how to capture them programmatically.

**`validate.md`** (64 lines) — Says "run 7-Question Gate" but does not implement or reference the triage-validation agent's logic.

**Recommendation:** Either flesh out these pipeline agents with actual tool call workflows, or merge them into `autopilot.md` as inline steps. The 20-line `scope.md` in particular adds no value over a verbal checklist.

**Severity:** Low — usability issue, not a bug.
**Effort:** Small (1hr to flesh out) or merge into autopilot

### 3.3 Bloated Agents

**`bug-bounty.md`** (2,236 lines) — Contains the entire bug bounty methodology including 26 H1 report tables, complete payload lists, and a full SSRF cloud metadata guide. This is too large for a single agent file. The 7-phase workflow, mindset frameworks, and payload data should be split into reference files.

**`osint-methodology.md`** (1,674 lines) — Similar issue. Contains complete tool documentation (theHarvester, SpiderFoot, Maltego, etc.) that belongs in reference docs.

**Impact:** LLM context window pressure. When these agents load, they consume 1.5-2K+ lines of prompt space, crowding out the actual conversation.

**Recommendation:** Extract payload data, tool docs, and reference tables into `knowledge/` or `prompts/` files. Keep agent files as concise workflow instructions (<300 lines).

**Severity:** Medium — context window waste.
**Effort:** Medium (2-3hr to refactor)

### 3.4 Agent Overlap Analysis

| Overlapping Pair | Overlap Area | Assessment |
|-----------------|--------------|------------|
| `hunt-mass-assignment` + `hunt-api-misconfig` | Both cover extra fields in JSON bodies, admin flag escalation | Real overlap — mass assignment is a subset of API misconfig. Merge or cross-reference. |
| `hunt-prototype-pollution` + `hunt-api-misconfig` | PP is often found via API parameter fuzzing | Minor overlap — keep separate as PP has distinct exploit chains |
| `hunt-crlf` + `hunt-http-smuggling` | CRLF can enable smuggling | Related but distinct techniques. CRLF is header injection, smuggling is request parsing. Keep separate with cross-refs. |
| `hunt-clickjacking` + `hunt-misc` | Clickjacking is often a "misc" finding | `hunt-clickjacking` is justified as standalone — it has specific tests (WSTG-CLNT-09) |
| `hunt-sqli` + `hunt-nosqli` | Both injection into databases | Different syntax, different databases. Keep separate. |
| `hunt-ssrf` + `hunt-lfi` | Both involve URL/file fetching | Different primitives. Keep separate. |

**Recommendation:** Cross-reference overlapping agents in their frontmatter. E.g., `hunt-api-misconfig` should say "See also: `hunt-mass-assignment` for mass assignment-specific tests."

**Severity:** Low — organizational, not broken.
**Effort:** Small (add cross-references)

### 3.5 Frontmatter Inconsistency

**11 agents lack proper frontmatter** (no `description:` / `mode:` / `permission:` fields):
- `autopilot.md`, `capture.md`, `consult.md`, `exploit.md`, `hunt.md`, `pintel.md`, `recon.md`, `report.md`, `scope.md`, `surface.md`, `validate.md`

**12 agents lack `permission:` section:**
- Same 11 as above + `web2-vuln-classes.md`

**Impact:** OpenCode may not auto-load these agents correctly. Without `description:` and `mode:` frontmatter, the agent routing/loading system cannot match keywords or determine execution mode.

**Recommendation:** Add consistent frontmatter to all 83 files:
```yaml
---
description: <concise 1-line description>
mode: subagent
permission:
  read: allow
  bash: deny  # or allow where needed
  edit: deny
  grep: allow
  glob: allow
---
```

**Severity:** High — agents may not load correctly.
**Effort:** Small (30min to add frontmatter to 12 files)

### 3.6 Broken References in Agents

**Agents referencing `bash scripts/payloads/<name>/test.sh`:**
- `hunt-clickjacking.md` — `bash scripts/payloads/clickjacking/test.sh <engagement-id>` — **this file EXISTS**
- `hunt-crlf.md` — `bash scripts/payloads/crlf/test.sh <engagement-id>` — **this file EXISTS**

**Agents referencing `bash scripts/payloads/<name>/` without test.sh:**
- `hunt-dependency-confusion.md` — references `scripts/payloads/dependency-confusion/test.sh` — **this file EXISTS**
- `hunt-http-param-pollution.md` — references `scripts/payloads/http-param-pollution/test.sh` — **this file EXISTS**
- `hunt-mass-assignment.md` — references `scripts/payloads/mass-assignment/test.sh` — **this file EXISTS**
- `hunt-prototype-pollution.md` — references `scripts/payloads/prototype-pollution/test.sh` — **this file EXISTS**

All referenced test scripts exist. The `knowledge/payloads/` directory has 74 categories, of which only 6 have corresponding `scripts/payloads/` test scripts. The agents that reference `knowledge/payloads/<category>/README.md` (like `hunt-xss.md` line 31) — these READMEs exist as part of the PayloadsAllTheThings submodule, but may or may not be cloned properly.

**WSTG test ID references:**
- `hunt-xss.md` correctly references `WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01`
- `hunt-clickjacking.md` correctly references `WSTG-CLNT-09`
- `hunt-crlf.md` references `WSTG-INPV-15` — this exists (HTTP Parameter Pollution)
- `bug-bounty.md` uses `test_id="All phases (Bug Bounty)"` which is non-standard

**MCP tool prefix usage:**
- `scope.md` uses un-prefixed `register_scope()` — should be `wstg_register_scope()`
- Pipeline agents (scope/autopilot) use `wstg_` prefix consistently
- Hunt agents (xss, clickjacking) use un-prefixed `get_wstg_test()`, `log_finding()`, `findings_add_vuln()`, `track_test()`, `generate_report()`

**Impact:** Agents that reference `wstg_` prefixed tools will work with the current MCP server. Agents using un-prefixed names may fail or rely on OpenCode's tool routing to match the MCP tool names.

**Recommendation:** Standardize on `wstg_` prefix for all agent tool references. Fix un-prefixed tool names across all 83 agents.

**Severity:** Medium — tool routing may silently fail.
**Effort:** Medium (1hr to bulk-fix all agents)

### 3.7 Agent Description/Mode Distribution

| Description | Count |
|-------------|-------|
| Has `description:` in frontmatter | 72 |
| Has `mode: subagent` | 72 |
| Has `permission:` block | 71 |
| Missing frontmatter entirely | 11 |

---

## 4. Knowledge & Data Files

### 4.1 WSTG v4.2 Coverage

**109 test files** across 12 categories. File counts per category:

| Category | Code | Files | Status |
|----------|------|-------|--------|
| Information Gathering | INFO | 9 | Complete |
| Configuration | CONF | 10 | Complete |
| Identity Management | IDNT | 5 | Complete |
| Authentication | ATHN | 12 | Complete |
| Authorization | ATHZ | 7 | Complete |
| Session Management | SESS | 9 | Complete |
| Input Validation | INPV | 20 | Complete |
| Error Handling | ERRH | 3 | Complete |
| Cryptography | CRYP | 3 | Complete |
| Business Logic | BUSL | 10 | Complete |
| Client-Side | CLNT | 15 | Complete |
| API Testing | APIT | 6 | Complete |

One discrepancy: `server_data.py` lists 12 categories, `knowledge/wstg/` has 12 directories — matching. The README says "96 test cases" but `find . -name "WSTG-*.md" | wc -l` returns 109. Inconsistency likely from counting only distinct IDs vs actual files.

**Recommendation:** Update README to say "109 WSTG test cases."

### 4.2 WAF Fingerprints

- **`server/waf_vendors.json`**: 144 vendor signatures (inline in `waf_evasion.py` + JSON file)
- **`knowledge/waf/waf-knowledge-base/02-waf-fingerprints/`**: ~110+ additional vendor fingerprints in markdown
- **`knowledge/waf/README.md`**: Claims 171 vendors total — the union of `waf_vendors.json` (144) + knowledge base fingerprints (~110+ unique)

The `waf_evasion.py` function `_identify_waf()` uses the inline `WAF_SIGNATURES` dict + `waf_vendors.json`. The knowledge/ directory content is not used by code — it's reference material for agents.

**Verification:** Summary.html false — 144 vendors in JSON ≠ 171 total. The discrepancy is 27 theoretical vendors from the Awesome-WAF KB that are in markdown but not in the JSON.

### 4.3 Payload Libraries

**`knowledge/payloads/`**: 64 directories (74 entries including .github, README, etc.). This appears to be a PayloadsAllTheThings submodule or clone. Contents range from 150-800 lines per category. Spot-check:

- `XSS Injection/` — 610 lines, complete with methodology and payloads
- `Clickjacking/` — 256 lines
- `CRLF Injection/` — 152 lines
- `SQL Injection/` — present

All directories appear populated. No empty/truncated payload files detected.

### 4.4 Wordlists

**`knowledge/wordlists/`**: Contains GF (grep-friendly) pattern files for parameter discovery. `summary.md` says "20 GF patterns" — matching the directory count.

### 4.5 Runtime Data in Git

**`server/data/`** is in `.gitignore:39` (`server/data/`). Verified: `git ls-files server/data/` returns nothing. However:

- The `.gitignore` line `server/data/` only works if `.gitignore` is in the root. It is. The trailing `/` ensures only a directory match.
- **Potential issue**: `encryption.key` at `server/data/encryption.key` would be exposed if `.gitignore` is bypassed (e.g., `git add -f`).
- The `server/data/` directory contains `findings.db`, `findings.db-shm`, `findings.db-wal`, and `encryption.key` — all properly ignored.

---

## 5. Scripts

### 5.1 `scripts/bughunt.py` (752 lines)

**Issue 1 (High): `urllib.request.urlopen()` without scheme restriction**
- `bughunt.py:121`: `urllib.request.urlopen("http://127.0.0.1:8080/")` — hardcoded to HTTP, safe in this instance
- `bughunt.py:140`: `urllib.request.urlopen(req, timeout=timeout)` — uses `urllib.request.Request` which could accept `file://` URIs if `url` parameter is attacker-controlled. The bandit tool flags this as B310.

**Recommendation:** Restrict scheme to `http://` and `https://` only using `urllib.parse.urlparse()`:
```python
scheme = urllib.parse.urlparse(url).scheme
if scheme not in ("http", "https"):
    raise ValueError(f"Unsupported URL scheme: {scheme}")
```

**Issue 2 (Medium): Bare except blocks**
- Line 125: `except Exception: pass` — silent failure when detecting Burp proxy
- Line 359: `except Exception: continue` — silent skip when reading skill files

**Recommendation:** Log at minimum: `logger.debug("Failed to read skill: %s", e)`

**Issue 3 (Low): `subprocess.call(["which", name])`**
Line 69 uses `which` to find executables. The bandit B607 flag is noise in this context — `which` is not a user-supplied path.

**Overall assessment:** `bughunt.py` is well-structured with clear error messages and exit codes. The `run_cmd()` function at line 72 correctly handles timeout, not-found, and permission errors. The 4 subcommands are cleanly separated.

### 5.2 `scripts/install.sh` (566 lines) + `scripts/setup.sh` (496 lines)

**Portability issues:**
1. **macOS compatibility**: Both scripts use `-z` flag with `BASH_SOURCE[0]` which is POSIX, but `tee -a` and `nohup` are available on macOS. The main issue is `apt-get` calls at install.sh:
   ```bash
   sudo apt-get install -y libpcap-dev build-essential ...
   ```
   No `brew` fallback for macOS. The `setup.sh` has `HAS_BREW=true` detection but only uses it for `pipx install` of `poetry`, never for system packages.

2. **WSL assumptions**: `reconnect-burp.sh` accesses `/mnt/c/Windows/System32/netstat.exe` — will fail on native Linux or macOS.

**Destructive operations:**
- Both scripts backup config to `~/.dristi/backups/` before overwriting — good practice
- `install.sh` runs `sudo apt-get install` with `-y` flag — non-interactive but could break existing packages
- `setup.sh` copies files to `~/.config/opencode/` — will overwrite existing OpenCode config

**Error handling:**
- Both use `set -euo pipefail` — correct
- `install.sh:46-47`: `exec > >(tee -a "$LOG_FILE") 2>&1` — logs all output, good practice

**Recommendation:** Add macOS/brew fallback for system packages. Document WSL requirement for `reconnect-burp.sh`.

### 5.3 `scripts/playwright-mcp.sh` + `scripts/playwright-stealth.js`

**Effectiveness assessment:**
- Proxy auto-detection is robust — checks WSL2 gateway, macOS, and native Linux
- Bypass list covers private ranges correctly
- User-Agent override at line 66 uses Chrome 122 — release date Feb 2024, now 2.5 years old. Should be updated to Chrome 130+ to avoid detection:
  ```bash
  PROXY_ARGS+=( "--user-agent" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" )
  ```

**Stealth script analysis (`playwright-stealth.js`):**
- Patches `navigator.webdriver` — correct, this is the #1 detection method
- Patches `navigator.plugins` — adds 3 plugins, adequate
- Patches `navigator.languages` — adds `['en-US', 'en', 'es', 'fr']`, adequate
- Overrides `permissions.query` — masks headless notification behavior
- Adds `window.chrome.runtime` — basic Chrome presence

**Missing patches:**
- `navigator.hardwareConcurrency` — headless often returns 4 or less; real machines have 8+
- `WebGL vendor/renderer` — headless WebGL differs from real GPU
- `screen dimensions` — headless often at 800x600; needs realistic values
- `navigator.connection` — headless may not have the NetworkInformation API

**Recommendation:** Add more stealth patches. Update User-Agent to current Chrome.

### 5.4 `scripts/reconnect-burp.sh` (191 lines)

**Kill logic reliability:**
```bash
STALE_PIDS=$(pgrep -f "mcp-proxy-all" 2>/dev/null || true)
kill $STALE_PIDS 2>/dev/null || true
```
Using `$STALE_PIDS` unquoted could cause issues with spaces. Should be:
```bash
kill "$STALE_PIDS" 2>/dev/null || true
```

The `pgrep -f` pattern `"mcp-proxy-all"` could match unintended processes. A more specific pattern like `"mcp-proxy-all.*burp"` would be safer.

The Python heredoc for toggling opencode config (lines 128-161) is clean and handles backup correctly.

**Recommendation:** Quote PID variables. Add SIGKILL fallback after SIGTERM timeout.

---

## 6. Testing

### 6.1 Coverage

| Module | Lines | Test Lines | Coverage (approx) |
|--------|-------|------------|-------------------|
| `server.py` | 6,444 | 139 | ~2% |
| `access_control.py` | 529 | 145 | ~27% |
| `state_manager.py` | 418 | 59 | ~14% |
| `findings_db.py` | 744 | 130 | ~17% |
| `waf_evasion.py` | 656 | 0 | 0% |
| `knowledge_graph.py` | 689 | 0 | 0% |
| `endpoint_priority.py` | 265 | 0 | 0% |
| `context_compression.py` | 384 | 0 | 0% |
| `task_tree.py` | 438 | 0 | 0% |
| `server_data.py` | 559 | 0 | 0% |
| `tool_parsers.py` | 660 | 0 | 0% |
| `tool_verification.py` | 450 | 0 | 0% |
| `crypto_utils.py` | 61 | 0 | 0% |
| **Total** | **12,297** | **602** | **~5%** |

**Critical gaps:**
- `waf_evasion.py` — 0 tests for WAF identification logic (the core IP of the WAF bypass system)
- `knowledge_graph.py` — 0 tests for chaining/query logic
- `tool_parsers.py` — 0 tests for any parser
- `tool_verification.py` — 0 tests for verification logic
- `crypto_utils.py` — 0 tests for encryption/decryption round-trip

### 6.2 Existing Test Quality

**`test_server_tools.py` (139 lines):** Tests the `_sanitize_id`, `_parse_wstg_file`, `_find_test_file`, `_validate_shell_arg`, `get_wstg_test`, `track_test`, and `_engagement_path` functions. These are unit tests that validate behavior rather than just asserting no crash. Good quality.

**`test_input_validation.py` (86 lines):** Reinements of the sanitization logic. Thorough edge case coverage for `_sanitize_id` and `_validate_shell_arg`. Tests path traversal, shell metacharacters, and truncation. **Note:** These test helper functions are duplicated from server.py — they don't test the actual server.py functions but reinements of them. This is a code clone anti-pattern.

**`test_state_manager.py` (59 lines):** Tests basic CRUD for checkpoints. Validates disk persistence and WAL logging. Adequate but minimal — doesn't test rollback, crash recovery, or concurrent access.

**`test_access_control.py` (145 lines):** Tests RBAC grant/revoke, locking, sessions. Validates expiration and concurrency. Good breadth but shallow depth.

**`test_findings_db.py` (130 lines):** Tests init, CRUD for hosts/vulns/credentials. Validates basic SQLite operations. Missing: edge cases (duplicate entries, empty strings, SQL injection in input fields).

### 6.3 Test Infrastructure

**`conftest.py` (43 lines):** Provides `temp_data_dir` fixture that uses `os.chdir()` for isolation. This is fragile — tests should use `tmp_path` (a pytest built-in fixture) instead of changing CWD. The `temp_engagements` fixture in `test_server_tools.py` uses the better pattern: monkey-patching `ENGAGEMENTS_DIR` instead of chdir.

**Recommendation:** Fix `conftest.py` to use `tmp_path` + monkey-patching instead of `os.chdir()`.

### 6.4 Most Critical Modules to Test

| Priority | Module | Reason |
|----------|--------|--------|
| P0 | `waf_evasion.py` | Core business logic, regex patterns, WAF identification |
| P0 | `crypto_utils.py` | Encryption correctness, key management, fallback behavior |
| P1 | `tool_parsers.py` | Would catch parser regressions when tools add output formats |
| P1 | `tool_verification.py` | Auto-correction logic could generate wrong commands |
| P1 | `knowledge_graph.py` | Graph traversal logic, chaining patterns |
| P2 | `findings_db.py` | Database CRUD — already partially tested, needs edge cases |

---

## 7. Configuration & Security

### 7.1 `.mcp.json` Analysis

```json
{
  "mcpServers": {
    "wstg-pentest": {
      "command": "uv",
      "args": ["--directory", "./server", "run", "server.py"]
    },
    "playwright": {
      "command": "bash",
      "args": ["./scripts/playwright-mcp.sh"]
    }
  }
}
```

**Issues:**
- Uses relative path `./server` — works only from the repo root
- No `env` block — no environment variables set
- No `disabled` flag — both servers always start

**No secrets or hardcoded credentials found.**

### 7.2 `.opencode/opencode.json`

**File does not exist.** The scripts reference `~/.config/opencode/opencode.json` (user's global config), but there is no project-level OpenCode config in the repo. The `.opencode/` directory exists but only contains `agents/`.

**Recommendation:** Add a `.opencode/opencode.json` with a default `agentGroups` configuration for the 83 agents, or document that the install.sh script handles this.

### 7.3 `.gitignore` Audit

| Pattern | Protects | Status |
|---------|----------|--------|
| `__pycache__/` | Python cache | OK |
| `venv/`, `.venv/` | Virtual envs | OK |
| `.env`, `.env.*` | Environment secrets | OK |
| `*.pem`, `*.key`, `*.crt`, etc. | TLS keys/certs | OK |
| `runtime/` | Pentest output with tokens/creds | OK |
| `configs/*.yaml` (except example) | User credentials | OK |
| `server/data/` | SQLite DB, encryption key, tracking | OK |
| `.playwright-mcp/` | Playwright logs | OK |
| `engagements/` | Engagement data | OK |

**Missing patterns:**
- `.opencode/opencode.json` — user OpenCode config (if it exists, should not be committed)
- `skills/` — are these generated or curated? If generated, they should be ignored.
- `*.db`, `*.db-shm`, `*.db-wal` — broad SQLite pattern would add safety
- `*.log` — already covered by `*.log` at the end

**No secrets found in git tracking.** Verified with `git ls-files server/data/` — empty.

### 7.4 Accidental Credential Exposure Risk

**Medium risk.** The `crypto_utils.py` fallback to plaintext (2.2) means credentials in the SQLite DB may be in plaintext. If `server/data/` was ever accidentally committed (e.g., before `.gitignore` was added), credentials would be in git history.

**Recommendation:** Check git history for `server/data/` existence. Use `git filter-branch` or `bfg-repo-cleaner` if found.

**No hardcoded API keys, tokens, or passwords found in the codebase.** The `configs/example-config.yaml` has placeholder values only.

### 7.5 `SECURITY.md` Assessment

The security policy at `SECURITY.md:9-13` correctly states the authorized-use posture — bug bounty programs, authorized pentests, CTFs, lab infrastructure. The "need to know / really useful" framing is appropriate for a pentest tool.

**One issue:** `SECURITY.md:4` mentions "external red-team jobs, authorized Penetration tests" but does not explicitly mention the legal requirement for **written authorization**. The README does mention this in its "Scope" section.

---

## 8. Documentation

### 8.1 `README.md` (855 lines)

**Accuracy:**
- Claims 86 MCP tools — actual count is 89 `@mcp.tool()` decorators (close enough; some may be undiscoverable or aliases)
- Claims 83 agents — actual count is 83 .md files in `.opencode/agents/` — **correct**
- Claims 96 WSTG test cases across 12 categories — actual count is 109 test files across 12 categories — **off by 13**
- Claims 20 GF patterns for parameter discovery — matches `knowledge/wordlists/` count
- Claims "8,300+ H1 Reports" in the shield badge — unverifiable from code

**Recommendation:** Fix the WSTG test count to 109. Verify the H1 report claim or remove it.

### 8.2 `summary.md` (365 lines)

**Accuracy:**
- Line 5: "86 tools, paired with 75 autonomous agents" — README says 86/83, summary says 86/75. **Inconsistent.** Correct: 89 tools, 83 agents.
- Line 14: "86 MCP tools · 75 agents" — again inconsistent with README
- Line 15: "13 WSTG categories" — actual is 12 (server_data.py has 12 categories, knowledge/wstg has 12 dirs). **Off by 1.**
- Line 38: "server.py — 86 tool definitions (6147 lines)" — actual is 89 tools, 6444 lines. Stale line count.
- Line 40: "waf_vendors.json — 144 vendor fingerprints" — matches actual count.

**Recommendation:** Sync summary.md with actual code. Fix all inconsistent numbers.

### 8.3 `testflow.md` (322 lines)

**Accuracy:**
- Lines 1: "11 pipeline agents" — actual pipeline agents in .opencode/agents/ are: `autopilot`, `scope`, `pintel`, `recon`, `surface`, `hunt`, `exploit`, `capture`, `validate`, `report` = 10. The `consult` agent is also interactive pipeline-like. Close enough.
- Line 1: "83 total" — matches.
- Uses `wstg_` prefix consistently — matches MCP server.
- Phase 2 "AUTHENTICATE" is now in autopilot.md's phase list — resolved by renumbering to sequential integers 1–12 (SCOPE=1, AUTH=2, INTEL=3, RECON=4, SURFACE=5, HUNT=6, DEEP-THINK=7, EXPLOIT=8, SEARCH-AGENT=9, CAPTURE=10, VALIDATE=11, REPORT=12).

**Phase numbering consistency resolved:** Both autopilot.md and testflow.md now use 1–12 sequential integer phases (no decimals).

### 8.4 Other Docs

| File | Assessment |
|------|------------|
| `docs/architecture.md` | Not read in detail, but summary.md tracks the same content |
| `docs/burp-flow.md` | Not verified — likely matches the agent references |
| `docs/browser-flow.md` | Likely matches playwright-mcp.sh |
| `docs/deep-testing.md` | Referenced by hunt-xss.md but not verified |
| `docs/ENGAGEMENTS.md` | Likely matches the engagement management tools |
| `docs/ENTERPRISE.md` | Covers enterprise attack chains |
| `docs/workflow.md` | Uses MCP tool names correctly |
| `docs/skills.md` | References the skills directory |

**Recommendation:** Cross-verify all docs against actual code for stale references. The `summary.md` numbers are the most stale.

---

## 9. Ranked Action Plan

### P0 — Must Fix (security bugs, data loss risk, broken functionality)

| # | Area | Issue | Fix |
|---|------|-------|-----|
| P0.1 | 2.3 | `validate_poc()` uses `shell=True` with unsanitized input | Replace with `shlex.split()` + `shell=False`. **Effort: Small** |
| P0.2 | 1.4 | Encryption silently disabled when `cryptography` missing; `[encrypt]` extra is empty | Make `cryptography` required, or fix the extra. Add startup warning. **Effort: Small** |
| P0.3 | 2.2 | `crypto_utils.decrypt_secret()` returns plaintext on failure | Raise exception on decrypt failure. **Effort: Small** |
| P0.4 | 3.5 | 11 agents lack frontmatter — won't load in OpenCode | Add `description`, `mode`, `permission` to all 11. **Effort: Small** |
| P0.5 | 7.3 | `.gitignore` may not protect `server/data/` from `git add -f` | Add `.gitattributes` with `server/data/* linguist-generated` or a pre-commit hook. **Effort: Small** |

### P1 — Should Fix (correctness, usability, maintainability)

| # | Area | Issue | Fix |
|---|------|-------|-----|
| P1.1 | 1.1 | 6,444-line monolith in `server.py` | Split into domain modules. **Effort: Medium** |
| P1.2 | 2.6 | Thread-local SQLite schema not initialized per-connection | Move schema init into per-thread connection getter. **Effort: Small** |
| P1.3 | 3.6 | Agent tool references use mixed `wstg_` and un-prefixed names | Standardize all agent tool references. **Effort: Medium** |
| P1.4 | 5.1 | `bughunt.py` uses `urllib.urlopen` without scheme restriction | Add scheme validation. **Effort: Small** |
| P1.5 | 5.3 | Stale User-Agent in playwright-mcp.sh (Chrome 122) | Update to Chrome 130+ and add stealth patches. **Effort: Small** |
| P1.6 | 6.1 | ~0% test coverage for 9 of 13 modules | Add tests for `waf_evasion`, `crypto_utils`, `tool_parsers`, `tool_verification`, `knowledge_graph`. **Effort: Large** |
| P1.7 | 6.3 | `conftest.py` uses `os.chdir()` instead of `tmp_path` | Replace with `tmp_path` + monkey-patching. **Effort: Small** |
| P1.8 | 3.3 | `bug-bounty.md` (2,236 lines) and `osint-methodology.md` (1,674 lines) too large | Extract payloads/references to knowledge/ files. **Effort: Medium** |
| P1.9 | 1.2 | Global `configure()` pattern with no guards | Add `_configured` flags and assertions. **Effort: Medium** |
| P1.10 | 5.2 | `install.sh` has no macOS/brew fallback for system packages | Add brew-based package installation. **Effort: Medium** |

### P2 — Nice to Fix (code style, docs, minor refactoring)

| # | Area | Issue | Fix |
|---|------|-------|-----|
| P2.1 | 8.2 | `summary.md` has stale numbers (86 tools → 89, 75 agents → 83, 13 WSTG → 12) | Update all numbers to match code. **Effort: Small** |
| P2.2 | 8.1 | README claims 96 WSTG tests, actual is 109 | Fix README count. **Effort: Small** |
| P2.3 | 1.3 | `access_control.py` (529 lines) and `state_manager.py` (418 lines) are unused dead code | Either expose tools or remove. **Effort: Large** |
| P2.4 | 3.2 | `scope.md` (20 lines), `report.md` (34 lines) too thin to be useful | Flesh out or merge into autopilot. **Effort: Small** |
| P2.5 | 3.4 | Agent overlaps not cross-referenced | Add `See also` notes to overlapping agents. **Effort: Small** |
| P2.6 | 2.1 | 8 mypy errors, 29 with full strict mode | Fix annotations, enable stricter mypy. **Effort: Medium** |
| P2.7 | 2.4 | `.bandit` skips 27 categories, too broad for a security tool | Narrow skip list, keep only justified skips. **Effort: Small** |
| P2.8 | 5.3 | Playwright stealth script missing modern patches | Add WebGL, hardwareConcurrency, screen patches. **Effort: Small** |
| P2.9 | 5.4 | `reconnect-burp.sh` unquoted PID variable | Quote `$STALE_PIDS` and all expansions. **Effort: Small** |
| P2.10 | 7.5 | SECURITY.md doesn't explicitly require written authorization | Add "You must have written authorization" statement. **Effort: Small** |
| P2.11 | 6.2 | `test_input_validation.py` duplicates server.py code | Import from server.py instead of reinementing. **Effort: Small** |
| P2.12 | 8.3 | `testflow.md` uses 1-indexed phases, `autopilot.md` uses 0-indexed | Unify phase numbering. **Effort: Small** |

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Server Python modules | 13 |
| Total server lines | 12,297 |
| Server monolith (`server.py`) | 6,444 lines (52%) |
| MCP tools | 89 (claimed 86) |
| Agent files | 83 (matches claim) |
| Agents missing frontmatter | 11 |
| Agents missing permissions | 12 |
| WSTG test files | 109 (claimed 96) |
| WAF vendor fingerprints | 144 (claimed 171) |
| Payload categories | 64 |
| Scripts | ~27 |
| Test files | 5 |
| Test code | 602 lines |
| Test coverage | ~5% |
| Mypy errors | 8 (29 with strict mode) |
| Bandit issues (real) | ~3-4 |
| Shell injection risk | 2 `shell=True` calls |
| eval/exec/pickle usage | None in project code |
| Dead code (estimate) | ~950 lines (access_control + state_manager) |
| Docs inconsistencies | summary.md numbers stale, README WSTG count off |
| P0 issues | 5 |
| P1 issues | 10 |
| P2 issues | 12 |

---

*End of review.*
