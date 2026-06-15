#!/usr/bin/env python3
# Burp MCP bridge — auto-detects WSL vs native Linux then connects accordingly.
#
# Behaviour:
#   WSL2        → Gets Windows host IP from default gateway, connects via burp_proxy.py (port 9872)
#   Native      → Connects directly to 127.0.0.1:9876 (Kali/Parrot/Ubuntu/macOS)
#
# Usage (invoked by opencode.json mcp.burp entry):
#   python3 burp-mcp-bridge.py

import sys, json, threading, requests, urllib.parse, os, time, signal, socket

SSE_TIMEOUT = 30
RETRY_DELAYS = [1, 2, 4, 8, 16]

session_id = [None]
ready = threading.Event()
running = True
sse_thread_ref = [None]

# ── Platform detection ──────────────────────────────────────────────────────

def is_wsl():
    return (
        os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop")
        or bool(os.environ.get("WSL_DISTRO_NAME"))
    )

def get_windows_ip():
    """Resolve Windows host IP from WSL2 default gateway."""
    try:
        result = subprocess.run(
            ["ip", "route"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if line.startswith("default via "):
                return line.split()[2]
    except Exception:
        pass
    return "172.17.160.1"  # fallback

# ── SSE & JSON-RPC ─────────────────────────────────────────────────────────

def sse_loop(burp_url):
    global session_id
    delay_idx = 0
    while running:
        try:
            resp = requests.get(
                burp_url,
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=None,
            )
            delay_idx = 0
            event_type = [None]
            data = []
            for line in resp.iter_lines(decode_unicode=True):
                if not running:
                    resp.close()
                    return
                if line is None:
                    continue
                if line.startswith("event: "):
                    event_type[0] = line[7:]
                elif line.startswith("data: "):
                    data.append(line[6:])
                elif line == "":
                    if event_type[0] == "endpoint":
                        body = "".join(data)
                        qs = body.split("?", 1)[1] if "?" in body else body
                        p = urllib.parse.parse_qs(qs)
                        session_id[0] = p.get("sessionId", [None])[0]
                        ready.set()
                    elif event_type[0] == "message":
                        sys.stdout.write("".join(data) + "\n")
                        sys.stdout.flush()
                    event_type[0] = None
                    data = []
        except Exception:
            pass
        if running:
            delay = RETRY_DELAYS[min(delay_idx, len(RETRY_DELAYS) - 1)]
            delay_idx += 1
            time.sleep(delay)


def signal_handler(signum, frame):
    global running
    running = False


def main():
    global running
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # ── Resolve Burp MCP endpoint ────────────────────────────────────────────
    if is_wsl():
        win_ip = get_windows_ip()
        burp_url = f"http://{win_ip}:9872/"
        sys.stderr.write(f"[burp-bridge] WSL detected → proxy at {burp_url}\n")
    else:
        burp_url = "http://127.0.0.1:9876/"
        sys.stderr.write(f"[burp-bridge] Native Linux → direct {burp_url}\n")

    t = threading.Thread(target=sse_loop, args=(burp_url,), daemon=True)
    sse_thread_ref[0] = t
    t.start()

    if not ready.wait(timeout=SSE_TIMEOUT):
        err = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32000,
                    "message": f"Timeout connecting to Burp MCP at {burp_url}",
                },
            }
        )
        sys.stdout.write(err + "\n")
        sys.stdout.flush()
        sys.exit(1)

    # Relay stdin → Burp MCP
    for line in sys.stdin:
        if not running:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            post_url = f"{burp_url}?sessionId={session_id[0]}"
            requests.post(
                post_url,
                json=msg,
                headers={"Content-Type": "application/json"},
                timeout=60,
            )
        except Exception as e:
            if "id" in msg:
                sys.stdout.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "error": {"code": -32002, "message": str(e)},
                        }
                    )
                    + "\n"
                )
                sys.stdout.flush()

    running = False


if __name__ == "__main__":
    # subprocess is only used in get_windows_ip() which runs only on WSL
    import subprocess
    main()
