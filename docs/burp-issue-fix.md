# Burp MCP Connection Fix — Detailed Technical Write-Up

## Problem

OpenCode in WSL2 could not connect to Burp Suite's MCP Server running on Windows. Two distinct failures occurred:

### 1. Source IP Block (403 Forbidden)

Burp MCP Server binds to `127.0.0.1:9876` and rejects connections from non-localhost source IPs. In WSL2, the Windows `127.0.0.1` is not reachable from Linux — WSL2 gets its own virtual network interface with a separate IP (e.g. `172.17.x.x`).

A `netsh interface portproxy` forwards `0.0.0.0:9876` → `127.0.0.1:9876`, but the portproxy **preserves the original source IP**. So Burp still sees the WSL VM IP and returns 403.

### 2. Protocol Mismatch (SSE vs Streamable HTTP)

Burp MCP Server uses the **SSE transport** (older MCP transport):
- `GET /` with `Accept: text/event-stream` establishes a persistent SSE connection
- Server sends `event: endpoint` → `data: ?sessionId=<uuid>`
- Client sends JSON-RPC via `POST /?sessionId=<uuid>` (gets `202 Accepted`)
- Responses arrive as `event: message` on the SSE stream

OpenCode uses the **Streamable HTTP transport** (newer MCP transport) for `"type": "remote"`:
- `GET /` expects a direct SSE endpoint
- Responses are expected in the POST response body, not streamed via SSE
- Sends `Origin` header which Burp MCP rejects with 403

### 3. Failed Workarounds

| Attempt | Result |
|---------|--------|
| Direct `localhost:9876` from WSL | Connection refused (WSL2 can't reach Windows `127.0.0.1`) |
| `netsh portproxy` `0.0.0.0:9876` → `127.0.0.1:9876` | 403 Forbidden (source IP preserved) |
| `Start-Process` TCP proxy on Windows | 403 Forbidden (source IP preserved) |
| `"type": "remote"` in OpenCode config | 403 + protocol mismatch |

---

## Solution: 2-Layer Proxy Chain (Current Architecture)

```
 OpenCode         WSL (Linux)                      Windows
┌──────────┐    ┌──────────────────┐    ┌───────────────────────┐    ┌──────────────┐
│ "type":  │    │ burp-mcp-bridge  │    │ Python TCP Proxy     │    │ Burp MCP     │
│ "local"  │◄──►│ (stdio ↔ HTTP)   │◄──►│ (Host rewrite +      │◄──►│ 127.0.0.1    │
│ stdio    │    │ connects directly│    │  Origin strip)       │    │ :9876        │
│ MCP      │    │ to Windows IP    │    │ 0.0.0.0:9872         │    │              │
└──────────┘    └──────────────────┘    └───────────────────────┘    └──────────────┘
```

This is the **simplified architecture** (2 layers instead of original 3). The WSL forwarder was removed — the bridge connects directly to the Windows proxy IP.

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

### Layer 2: MCP stdio Bridge (`burp-mcp-bridge.py`)

**File:** `/home/pwn/dristi/scripts/burp-mcp-bridge.py`

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

Automates proxy deployment, verification, and config toggling:

```
Step 1: Clean up stale bridge processes
Step 2: Check Burp MCP on Windows (port 9876)
Step 3: Copy & start Windows Python proxy (port 9872)
Step 4: Verify the proxy chain via SSE
Step 5: Toggle OpenCode config (forces reconnect)
Step 6: Restart Dristi WSTG server
```

### Windows Path Auto-Detection

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

**File:** `~/.config/opencode/opencode.json`

```json
{
  "mcp": {
    "burp": {
      "type": "local",
      "command": ["python3", "/home/pwn/dristi/scripts/burp-mcp-bridge.py"]
    }
  }
}
```

`"type": "local"` is critical — OpenCode spawns the bridge as a child process and communicates via stdio (JSON-RPC lines). `"type": "remote"` (Streamable HTTP) cannot handle Burp's SSE transport.

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

### Current (2-Layer)

```
OpenCode ↔ burp-mcp-bridge → Windows Proxy (172.17.x.x:9872) → Burp MCP (127.0.0.1:9876)
```

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
  | python3 /home/pwn/dristi/scripts/burp-mcp-bridge.py

# Direct SSE test against proxy
curl -s -N -H "Accept: text/event-stream" http://172.17.160.1:9872/
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
