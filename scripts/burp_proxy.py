#!/usr/bin/env python3
import socket, threading, re, os, signal, sys

def bridge(src, dst, src_to_dst=True):
    try:
        if src_to_dst:
            buf = src.recv(65536)
            if not buf:
                return
            data = buf.decode('utf-8', errors='replace')
            data = re.sub(r'Host: [^\r\n]+', 'Host: localhost:9876', data)
            data = re.sub(r'\r\nOrigin: [^\r\n]+', '', data)
            dst.sendall(data.encode('utf-8'))
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        else:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
    except:
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass

def handle(conn, addr):
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target.bind(('127.0.0.1', 0))
    target.connect(('127.0.0.1', 9876))
    threading.Thread(target=bridge, args=(conn, target, True), daemon=True).start()
    threading.Thread(target=bridge, args=(target, conn, False), daemon=True).start()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 9872))
srv.listen(50)
print('Proxy on :9872 -> 127.0.0.1:9876 (Host rewritten, Origin stripped)', flush=True)
while True:
    try:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except:
        pass
