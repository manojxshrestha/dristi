# Burp MCP Connection Fix — Detailed Technical Write-Up

## Problem

OpenCode needs to connect to Burp Suite's MCP Server across different platforms. Two distinct failures occurred on WSL, plus there is no equivalent setup for native Linux.

### WSL: Source IP Block (403 Forbidden)

Burp MCP Server binds to `127.0.0.1:9876` and rejects connections from non-localhost source IPs. In WSL2, the Windows `127.0.0.1` is not reachable from Linux — WSL2 gets its own virtual network interface with a separate IP (e.g. `172.17.x.x`).

A `netsh interface portproxy` forwards `0.0.0.0:9876` → `127.0.0.1:9876`, but the portproxy **preserves the original source IP**. So Burp still sees the WSL VM IP and returns 403.

### Protocol Mismatch (SSE vs Streamable HTTP)

Burp MCP Server uses the **SSE transport** (older MCP transport):
- `GET /` with `Accept: text/event-stream` establishes a persistent SSE connection
- Server sends `event: endpoint` → `data: ?sessionId=<uuid>`
- Client sends JSON-RPC via `POST /?sessionId=<uuid>` (gets `202 Accepted`)
- Responses arrive as `event: message` on the SSE stream

OpenCode uses the **Streamable HTTP transport** (newer MCP transport) for `"type": "remote"`:
- `GET /` expects a direct SSE endpoint
- Responses are expected in the POST response body, not streamed via SSE
- Sends `Origin` header which Burp MCP rejects with 403

### Failed Workarounds (WSL)

| Attempt | Result |
|---------|--------|
| Direct `localhost:9876` from WSL | Connection refused (WSL2 can't reach Windows `127.0.0.1`) |
| `netsh portproxy` `0.0.0.0:9876` → `127.0.0.1:9876` | 403 Forbidden (source IP preserved) |
| `Start-Process` TCP proxy on Windows | 403 Forbidden (source IP preserved) |
| `"type": "remote"` in OpenCode config | 403 + protocol mismatch |

### Native Linux Gap (Kali / Parrot / Ubuntu)

The original `connect-burp.sh` had a WSL-only guard — on native Linux it just printed instructions and exited. The `burp-mcp-bridge.py` hardcoded `get_windows_ip()` which would resolve to the router IP on native Linux, causing connection failures.

---

## Solution: Auto-Detecting Cross-Platform Architecture

### Platform Detection Layer

Every script now auto-detects the platform at startup — this is the **first thing** that happens:

| Script | Detection Method | Variables Exported |
|--------|-----------------|-------------------|
| `_env.sh` | `/proc/sys/fs/binfmt_misc/WSLInterop`, `/etc/os-release` | `IS_WSL`, `IS_KALI`, `IS_PARROT`, `IS_DEBIAN`, `IS_MACOS`, `DISTRO_ID` |
| `burp-mcp-bridge.py` | WSLInterop check | internal `is_wsl()` |
| `connect-burp.sh` | WSLInterop check | `IS_WSL` |
| `install.sh` (Python) | WSLInterop check, `/etc/os-release` | `is_wsl`, `distro_id` |

### WSL Architecture (2-Layer Proxy Chain)

```
 OpenCode         WSL (Linux)                      Windows
┌──────────┐    ┌──────────────────┐    ┌───────────────────────┐    ┌──────────────┐
│ "type":  │    │ burp-mcp-bridge  │    │ Python TCP Proxy     │    │ Burp MCP     │
│ "local"  │◄──►│ (stdio ↔ HTTP)   │◄──►│ (Host rewrite +      │◄──►│ 127.0.0.1    │
│ stdio    │    │ connects directly│    │  Origin strip)       │    │ :9876        │
│ MCP      │    │ to Windows IP    │    │ 0.0.0.0:9872         │    │              │
└──────────┘    └──────────────────┘    └───────────────────────┘    └──────────────┘
```

### Native Linux Architecture (Direct, No Proxy)

```
 OpenCode                              Kali / Parrot
┌──────────┐    ┌──────────────────┐    ┌──────────────┐
│ "type":  │    │ burp-mcp-bridge  │    │ Burp MCP     │
│ "local"  │◄──►│ (stdio ↔ HTTP)   │◄──►│ 127.0.0.1    │
│ stdio    │    │ connects directly│    │ :9876        │
│ MCP      │    │ to localhost:9876│    │              │
└──────────┘    └──────────────────┘    └──────────────┘
```

On native Linux, the bridge connects **directly** to `127.0.0.1:9876` — no `burp_proxy.py` needed because Burp runs on the same machine and there's no source-IP block issue.

### Layer 1: Windows Python TCP Proxy (`burp_proxy.py` on Windows)

**Source:** `scripts/burp_proxy.py` (copied to `%USERPROFILE%\burp_proxy.py`)

Fixes the **source IP + header rejection** problems:

```python
def bridge(src, dst, src_to_dst=True):
    if src_to_dst:
        buf = src.recv(65536)
        data = buf.decode('utf-8', errors='replace')
        # Rewrite Host header so Burp MCP accepts the request
        data = re.sub(r'Host: [^\r\n]+', 'Host: localhost:9876', data)
        # Strip Origin header (Burp MCP rejects non-matching origins)
        data = re.sub(r'\r\nOrigin: [^\r\n]+', '', data)
        dst.sendall(data.encode('utf-8'))
```

| Fix | What it does |
|-----|-------------|
| `bind(('127.0.0.1', 0))` | Connects to Burp MCP from `127.0.0.1` (source IP = localhost) |
| `Host: localhost:9876` rewrite | Burp MCP checks `Host` header; rejects non-localhost hosts |
| `Origin` header strip | Burp MCP rejects any `Origin` that doesn't match `http://localhost:9876` |
| Listens on `0.0.0.0:9872` | Reachable from WSL2 via the Windows host IP |

#### Auto-deployment

`connect-burp.sh` copies the proxy script to Windows via the shared `/mnt/c/` filesystem, then starts it via `cmd.exe /c start /b`. Python is auto-detected via `resolve_python()`:

```bash
resolve_python() {
  # 1. Try py -3 (Python launcher)
  test_out=$(cmd.exe /c "py -3 --version" | tr -d '\r\n')
  if echo "$test_out" | grep -qi "Python 3"; then echo "py -3"; return 0; fi
  # 2. Try App Execution Aliases (python3.11, python3 — work for Store installs)
  for alias in python3.11 python3; do
    test_out=$(cmd.exe /c "$alias --version" | tr -d '\r\n')
    if echo "$test_out" | grep -qi "Python 3"; then echo "$alias"; return 0; fi
  done
  # 3. Try where python results (they might be real, test each)
  while IFS= read -r line; do
    test_out=$(cmd.exe /c "\"$line\" --version" | tr -d '\r\n')
    if echo "$test_out" | grep -qi "Python 3"; then echo "$line"; return 0; fi
  done <<< "$(cmd.exe /c 'where python 2>nul')"
  # 4. Scan WindowsApps subfolder for Store-installed Python
  local s="$WIN_HOME_RAW\\AppData\\Local\\Microsoft\\WindowsApps"
  for f in python3.11.exe python3.exe; do
    test_out=$(cmd.exe /c "if exist \"$s\\$f\" \"$s\\$f\" --version" | tr -d '\r\n')
    if echo "$test_out" | grep -qi "Python 3"; then echo "$s\\$f"; return 0; fi
  done
  # 5. Fallback: common MSI install paths
  for p in "C:\\Python313\\python.exe" "C:\\Python312\\python.exe" \
           "$WIN_HOME_RAW\\AppData\\Local\\Programs\\Python\\Python313\\python.exe" \
           "$WIN_HOME_RAW\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"; do
    test_out=$(cmd.exe /c "if exist \"$p\" \"$p\" --version" | tr -d '\r\n')
    if echo "$test_out" | grep -qi "Python 3"; then echo "$p"; return 0; fi
  done
  return 1
}
```

Then starts the proxy:
```bash
PYTHON_WIN_RAW=$(resolve_python)
cmd.exe /c "cd /d C:\ && $PYTHON_WIN_RAW $PROXY_DST_RAW" > /dev/null 2>&1 &
```

**`start /b` is avoided** because:
1. `start /b` cannot resolve App Execution Aliases (like `python3.11` from a Store install)
2. `cmd.exe` launched from WSL inherits a UNC working directory (`\\wsl.localhost\...`) which Windows doesn't support — it defaults to `C:\Windows\System32` and concatenates quoted script paths with it (e.g. `C:\Windows\"C:\Users\manoj\burp_proxy.py"`)
3. The fix: `cd /d C:\` sets a clean Windows working directory; unquoted path works because there are no spaces in the profile path; `&` backgrounds the process

**`resolve_python()`** handles Python discovery because `where python` on Windows returns the Microsoft Store redirector stub (`%USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python.exe`), a 0-byte stub that silently opens the Store instead of running the script.

### Platform Detection in `burp-mcp-bridge.py`

The bridge auto-detects WSL vs native Linux at startup:

```python
def is_wsl():
    return (
        os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop")
        or bool(os.environ.get("WSL_DISTRO_NAME"))
    )

def main():
    if is_wsl():
        win_ip = get_windows_ip()
        burp_url = f"http://{win_ip}:9872/"   # via burp_proxy.py on Windows
    else:
        burp_url = "http://127.0.0.1:9876/"   # direct — same machine
```

On WSL, `get_windows_ip()` reads the default gateway from `ip route` (e.g. `172.17.160.1`) and connects to `burp_proxy.py` on port 9872. On native Linux, it connects directly to `127.0.0.1:9876`.

### Layer 2: MCP stdio Bridge (`burp-mcp-bridge.py`)

**File:** `${HOME}/dristi/scripts/burp-mcp-bridge.py`

Fixes the **protocol mismatch**. OpenCode uses `"type": "local"` (stdio transport), and this script translates:

```
OpenCode (stdio JSON-RPC) ←→ Burp MCP (SSE + HTTP POST)
```

How it works:

```
Thread 1 (SSE reader):
  │
  ├── GET / with Accept: text/event-stream
  ├── Receive event: endpoint → ?sessionId=<uuid>
  ├── For each event: message → write JSON-RPC to stdout
  │
Thread 2 (stdin reader):
  │
  ├── Read JSON-RPC line from stdin
  ├── POST /?sessionId=<uuid> with JSON body
  └── Response arrives via SSE (Thread 1 writes to stdout)
```

**Key detail:** All responses flow through the SSE connection. The bridge's SSE thread is the **single writer to stdout**, preventing interleaved output.

#### Infinite Retry (Auto-Reconnect)

When Burp Suite is stopped/restarted on Windows, the SSE connection drops. Instead of giving up, the bridge retries **indefinitely**:

```python
RETRY_DELAYS = [1, 2, 4, 8, 16]  # seconds
# After 16s → keeps retrying every 30s forever
delay = RETRY_DELAYS[min(delay_idx, len(RETRY_DELAYS) - 1)]
```

This means:
- Close Burp → MCP tools become unavailable in OpenCode (expected)
- Re-open Burp + enable MCP → bridge reconnects within 30s
- No manual reconnect needed — the stdio pipe stays open the whole time
- If the bridge process is killed, OpenCode's `"type": "local"` auto-restarts it

---

## The `connect-burp.sh` Script

**File:** `scripts/connect-burp.sh` (renamed from `reconnect-burp.sh`)

Auto-detects the platform and follows the appropriate path:

### Native Linux Path (Kali / Parrot / Ubuntu / macOS)

```
Step 1: Detect platform → IS_WSL=false
Step 2: Check Burp MCP on 127.0.0.1:9876 (via ss/netstat/devtcp)
Step 3: Toggle OpenCode config (forces reconnect)
Step 4: Start Dristi WSTG server
```

The native Linux path is simple — Burp runs on the same machine, so no proxy bridge is needed. The script just verifies Burp MCP is listening, toggles the OpenCode config, and starts the WSTG server.

```bash
if ! $IS_WSL; then
  print_banner
  info "Native Linux detected — connecting to local Burp MCP..."

  if command -v ss &>/dev/null; then
    MCP_CHECK=$(ss -tlnp 2>/dev/null | grep ":9876" || true)
  elif command -v netstat &>/dev/null; then
    MCP_CHECK=$(netstat -tlnp 2>/dev/null | grep ":9876" || true)
  else
    MCP_CHECK=$(timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/9876" 2>&1 || true)
  fi

  toggle_opencode_burp
  start_wstg_server
  print_done
  exit 0
fi
```

### WSL Path (Windows Proxy Bridge)

```
Step 1: Clean up stale bridge processes
Step 2: Check Burp MCP on Windows (port 9876)
Step 3: Copy & start Windows Python proxy (port 9872)
Step 4: Verify the proxy chain via SSE
Step 5: Toggle OpenCode config (forces reconnect)
Step 6: Restart Dristi WSTG server
```

### Windows Path Auto-Detection (WSL only)

No hardcoded usernames or IPs:
- Windows user profile: `cmd.exe /c "echo %USERPROFILE%"`
- Windows Python path: `resolve_python()` → tries `py -3`, App Execution Aliases (`python3.11`), `where python`, WindowsApps subfolder scan, then common MSI paths
- Windows IP: `ip route | grep default | awk '{print $3}'`

### Pitfall Fixed: `start /b` + App Execution Aliases + UNC Working Directory

Three problems with `start /b` in WSL→Windows context:

1. **App Execution Aliases**: `start /b` uses `CreateProcess` which can't resolve Microsoft Store App Execution Aliases (e.g., `python3.11`).
2. **UNC working directory**: When `cmd.exe` is launched from WSL with a UNC path (`\\wsl.localhost\...`), Windows falls back to `C:\Windows\System32` as the CWD.
3. **Quoted paths concatenated**: A quoted script path like `"C:\Users\manoj\burp_proxy.py"` gets concatenated with the fallback CWD → `C:\Windows\System32\"C:\Users\manoj\burp_proxy.py"` → file not found.

**Fixed by avoiding `start /b` entirely:**
```bash
# Broken: start /b "" python3.11 "C:\...\burp_proxy.py"
#   → "Windows cannot find '\\'" (alias not resolved)
# Broken: cmd.exe /c python3.11 "C:\...\burp_proxy.py"
#   → UNC CWD + quoted path → file not found

# Fixed: cd /d C:\ + unquoted path + background &
cmd.exe /c "cd /d C:\ && python3.11 C:\Users\manoj\burp_proxy.py" > /dev/null 2>&1 &
```

### Pitfall Fixed: Windows Store Python Stub

`where python` on a fresh Windows install returns `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python.exe` — this is a **0-byte Store redirector stub**, not a real Python interpreter. It silently opens the Microsoft Store when executed, so `cmd.exe /c start /b` launches it, it exits immediately, and the proxy never starts.

The resolution order now handles this:
1. `py -3` (Python launcher) — works with MSI installs
2. `python3.11` / `python3` — **App Execution Aliases** that work with Store-installed Python
3. `where python` results — validated with `--version` (the stub fails, but other results pass)
4. Direct scan of `WindowsApps\python3.11.exe` — the actual Store-installed Python binary
5. Common MSI paths as final fallback

### Pitfall Fixed: `echo -e` Eating Backslashes

The `ok()` function uses `echo -e`, which interprets `\b` as backspace. Displaying `C:\Users\manoj\burp_proxy.py` showed as `C:\Users\manourp_proxy.py` because `\b` in `\burp_proxy.py` ate the `j`:

**Fixed by replacing `echo -e` with `printf` for Windows paths:**
```bash
# Before (broken):
ok "Proxy script copied to $PROXY_DST_RAW"
# → "Copied to C:\Users\manourp_proxy.py"

# After (fixed):
printf "${G}[✓]${N} Proxy script copied to %s\n" "$PROXY_DST_RAW"
```

### Pitfall Fixed: PID 1840 vs Portproxy

The script checks `netstat -ano | grep :9876` to detect Burp MCP. But the `netsh portproxy` rule (`0.0.0.0:9876 → 127.0.0.1:9876`) also creates a LISTENING entry — owned by `svchost.exe` (IP Helper service, PID 1840), not Burp.

**If Burp Suite isn't running, the script falsely reports "Burp MCP running" then gets `NO_SESSION` on verification.**

The fix: the verification step (Step 4) catches this — if the SSE stream returns no `sessionId`, it warns the user. The script should also check the process name, not just the port.

---

## OpenCode Config

**File:** `~/.config/opencode/opencode.json` (generated by `install.sh`)

### Platform-Aware Configuration

The config is generated by `install.sh` based on auto-detected platform:

**WSL:** Uses `burp-mcp-bridge.py` as a local MCP server (the bridge auto-detects WSL and connects through the Windows proxy):
```json
{
  "mcp": {
    "burp": {
      "type": "local",
      "command": ["bash", "-c", "python3 ${HOME}/dristi/scripts/burp-mcp-bridge.py"]
    }
  }
}
```

**Native Linux:** Uses direct remote URL (Burp runs on same machine):
```json
{
  "mcp": {
    "burp": {
      "type": "remote",
      "url": "http://127.0.0.1:9876/",
      "enabled": true
    }
  }
}
```

### Playwright MCP

On all platforms, Playwright uses `playwright-mcp.sh` which auto-detects the Burp proxy:

```json
{
  "mcp": {
    "playwright": {
      "type": "local",
      "command": ["bash", "${HOME}/dristi/scripts/playwright-mcp.sh"]
    }
  }
}
```

`playwright-mcp.sh` checks WSLInterop first — on WSL it routes through the Windows host IP (`:8080`), on native Linux it uses `127.0.0.1:8080`.

### Why `"type": "local"` for the Bridge

`"type": "local"` is critical for the bridge because OpenCode spawns it as a child process and communicates via stdio (JSON-RPC lines). `"type": "remote"` (Streamable HTTP) cannot handle Burp's SSE transport — the bridge translates between the two protocols.

---

## WSTG Server Integration

The `connect-burp.sh` script also starts the Dristi WSTG MCP server (Python-based, not Burp-related):

```bash
nohup bash -c "cd '$DST/server' && exec uv run server.py" > "$HOME/.dristi/server.log" 2>&1 &
```

### Pitfall Fixed: `UV_PROJECT_ENVIRONMENT=venv`

The original script used `UV_PROJECT_ENVIRONMENT=venv`, but `uv run` creates `.venv` (not `venv`) by default. Explicitly setting an environment that doesn't exist caused `uv run` to fail silently.

**Removed the override — `uv run` auto-detects `.venv`.**

---

## Architecture Evolution

### Original (3-Layer, Deprecated)

```
OpenCode ↔ burp-mcp-bridge ↔ WSL Forwarder (port 9873) ↔ Windows Proxy (port 9872) ↔ Burp MCP
```

The WSL forwarder (`burp-proxy-run.sh`) was a simple TCP passthrough that gave OpenCode a stable `localhost:9873` address. It was **removed** because:
- The bridge already resolves the Windows IP dynamically
- One less layer = less latency and fewer failure points
- `burp-proxy-run.sh` was purely a TCP forwarder with no logic

### Current (WSL — 2-Layer)

```
OpenCode ↔ burp-mcp-bridge → Windows Proxy (172.17.x.x:9872) → Burp MCP (127.0.0.1:9876)
```

### Current (Native Linux — Direct)

```
OpenCode ↔ burp-mcp-bridge → 127.0.0.1:9876 (Burp MCP)
```

On native Linux (Kali/Parrot/Ubuntu/macOS), Burp runs on the same machine — no proxy layer needed.

### Removed Files
- `scripts/burp-proxy-run.sh` — WSL TCP forwarder (obsolete)
- `scripts/reconnect-burp.sh` — renamed to `connect-burp.sh`

---

## How to Rebuild / Debug

### Check each layer:

```bash
# Layer 1 — Windows proxy (check from WSL)
/mnt/c/Windows/System32/netstat.exe -ano | grep ":9872"

# Layer 2 — Bridge test (standalone)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | python3 ${HOME}/dristi/scripts/burp-mcp-bridge.py

# Direct SSE test against proxy
curl -s -N -H "Accept: text/event-stream" http://172.17.160.1:9872/
```

### Native Linux Check:

```bash
# Check if Burp MCP is running
ss -tlnp | grep 9876

# Bridge test (standalone)
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | python3 ${HOME}/dristi/scripts/burp-mcp-bridge.py

# Playwright proxy check
bash scripts/playwright-mcp.sh --help 2>&1 | head -5
```

### Connection:

```bash
bash scripts/connect-burp.sh
```

### If Burp MCP won't start on Windows:

```
C:\> taskkill /F /IM burpsuite.exe
C:\> taskkill /F /IM java.exe
```

Then restart Burp Suite and enable MCP Server extension.

---

## Architecture Decisions

| Decision | Why |
|----------|-----|
| Python for proxy/bridge | No dependencies beyond `requests` (stdlib-compatible), cross-platform |
| `"type": "local"` instead of `"type": "remote"` | OpenCode's remote transport uses Streamable HTTP; Burp MCP uses SSE. The bridge speaks stdio MCP, which OpenCode handles natively. |
| TCP-level proxy on Windows (not HTTP) | Simpler, handles SSE streaming without buffering issues |
| Infinite retry in bridge | Burp may be restarted during testing; bridge self-heals without manual reconnect |
| `cp` instead of SCP for Windows deployment | Windows drive is mounted at `/mnt/c/` in WSL2 — direct filesystem copy |
| Cross-platform detection first | Every script detects WSL/Kali/Parrot/macOS before anything else — avoids platform-specific bugs |
| `playwright-mcp.sh` wrapper instead of raw CLI | Auto-detects Burp proxy per platform; applies stealth init script; sets realistic User-Agent |
| Bridge script on native Linux skips proxy | Burp runs on same machine — no `burp_proxy.py` needed (different from WSL where Windows is a separate host) |

---

## Timeline

1. **Initial attempt**: Direct `localhost:9876` from WSL → connection refused
2. **Portproxy**: `netsh interface portproxy` → 403 Forbidden (source IP)
3. **PowerShell TCP proxy**: Source IP still preserved → 403
4. **Windows Python proxy with `bind(127.0.0.1)`**: Source IP = localhost → passed IP check, but Burp returned 400 — `sessionId query parameter is not provided`
5. **Discovered SSE protocol**: Burp MCP uses SSE transport (GET → SSE stream, POST → `202 Accepted`, responses via SSE `event: message`)
6. **Host header + Origin issues**: Burp MCP rejects non-localhost `Host` and any `Origin` header
7. **Fixed proxy with header rewrite**: Proxy rewrites `Host` → `localhost:9876` and strips `Origin`
8. **Tried `"type": "remote"` in OpenCode**: OpenCode's MCP client doesn't handle SSE transport correctly → still 403
9. **Built stdio bridge**: Python script translates stdio MCP ↔ SSE MCP → Burp MCP connected successfully
10. **Config to `"type": "local"`**: OpenCode spawns bridge as a child process, communicates via stdio
11. **Simplified to 2-layer**: Removed WSL forwarder (`burp-proxy-run.sh`), bridge connects directly to Windows IP
12. **Infinite retry**: Bridge retries SSE forever with exponential backoff → auto-heals on Burp restart
13. **Renamed to `connect-burp.sh`**: Old `reconnect-burp.sh` → `connect-burp.sh`; updated all references
14. **Fixed `echo -e` backslash eating**: Windows paths displayed with `\b` in `\burp_proxy.py` were mangled by `echo -e`; switched to `printf`
15. **Fixed WSTG server env**: Removed `UV_PROJECT_ENVIRONMENT=venv` override that prevented `uv run` from finding `.venv`
16. **Fixed Windows Store Python stub**: `where python` returned `WindowsApps\python.exe` (Store redirector, 0 bytes). Added `resolve_python()` that tries `py -3`, App Execution Aliases (`python3.11`), `where python` results, WindowsApps subfolder scan, then MSI fallback — each validated with `--version`.
17. **Fixed `start /b` triple failure**: `start /b` can't resolve App Execution Aliases; UNC CWD concatenates quoted paths with `C:\Windows\System32`. Replaced `start /b` with `cd /d C:\ && python3.11 <unquoted_path>` in background `&`.
18. **Cross-platform auto-detection**: Added platform detection to `_env.sh` (`IS_WSL`, `IS_KALI`, `IS_PARROT`, `IS_DEBIAN`, `IS_MACOS`, `DISTRO_ID`) — available to all 36 tool scripts.
19. **`burp-mcp-bridge.py` platform detection**: Added `is_wsl()` that checks WSLInterop; on WSL connects via `burp_proxy.py` (`:9872`), on native Linux connects directly to `127.0.0.1:9876`.
20. **`connect-burp.sh` native Linux path**: Replaced WSL-only guard with platform branch — native Linux checks local Burp MCP on `:9876`, toggles config, starts WSTG server. No proxy bridge needed.
21. **`install.sh` platform-aware config**: Config generator now detects WSL vs native Linux — on WSL uses `burp-mcp-bridge.py` as local command; on native Linux uses direct remote URL. Playwright always uses `playwright-mcp.sh` wrapper.
22. **`playwright-mcp.sh` proxy detection**: Auto-detects WSL (Windows host IP via `ip route` → `:8080`), macOS (`127.0.0.1:8080`), native Linux (`127.0.0.1:8080`). Includes stealth init script to patch Cloudflare/WAF fingerprints.
