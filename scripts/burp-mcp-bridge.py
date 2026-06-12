#!/usr/bin/env python3
import sys, json, threading, requests, urllib.parse, os, time, signal, socket, subprocess

SSE_TIMEOUT = 30
RETRY_DELAYS = [1, 2, 4, 8, 16]

session_id = [None]
ready = threading.Event()
running = True
sse_thread_ref = [None]

def get_windows_ip():
    try:
        result = subprocess.run(
            ["ip", "route"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if line.startswith("default via "):
                return line.split()[2]
    except:
        pass
    return None

def sse_loop(win_ip):
    global session_id
    burp_url = f"http://{win_ip}:9872/"
    delay_idx = 0
    while running:
        try:
            resp = requests.get(
                burp_url,
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=None
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
        except Exception as e:
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

    win_ip = get_windows_ip()
    if not win_ip:
        err = json.dumps({"jsonrpc": "2.0", "id": None,
                          "error": {"code": -32000, "message": "Cannot detect Windows IP"}})
        sys.stdout.write(err + "\n")
        sys.stdout.flush()
        sys.exit(1)

    t = threading.Thread(target=sse_loop, args=(win_ip,), daemon=True)
    sse_thread_ref[0] = t
    t.start()

    if not ready.wait(timeout=SSE_TIMEOUT):
        err = json.dumps({"jsonrpc": "2.0", "id": None,
                          "error": {"code": -32000, "message": "Timeout waiting for Burp MCP"}})
        sys.stdout.write(err + "\n")
        sys.stdout.flush()
        sys.exit(1)

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
            burp_url = f"http://{win_ip}:9872/?sessionId={session_id[0]}"
            requests.post(burp_url, json=msg,
                          headers={"Content-Type": "application/json"},
                          timeout=60)
        except Exception as e:
            if "id" in msg:
                sys.stdout.write(json.dumps(
                    {"jsonrpc": "2.0", "id": msg["id"],
                     "error": {"code": -32002, "message": str(e)}}) + "\n")
                sys.stdout.flush()

    running = False

if __name__ == "__main__":
    main()
