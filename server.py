"""
=============================================================
 Secure Remote Command Execution System  ─  SERVER
 Project  : Jackfruit Mini Project  (Deliverable 1)
 Language : Python 3
=============================================================
Features
  - SSL/TLS encrypted TCP connections (mandatory)
  - Username + SHA-256 password authentication
  - Whitelisted command execution (security)
  - Audit logging to logs/audit.log
  - Multi-threaded: handles multiple clients concurrently
=============================================================
"""

import socket, ssl, threading, json, subprocess
import hashlib, logging, datetime, os
from pathlib import Path

# ── Config ────────────────────────────────────────────────
HOST      = "0.0.0.0"
PORT      = 9999
CERT_FILE = "certs/server.crt"
KEY_FILE  = "certs/server.key"
LOG_FILE  = "logs/audit.log"

# Commands the server is allowed to run (whitelist)
ALLOWED = {
    "ls","pwd","whoami","date","echo","uname",
    "uptime","hostname","df","ps","cat",
    "head","tail","wc","grep","env","id"
}

# User credentials  { username: sha256(password) }
USERS = {
    "client1": hashlib.sha256(b"pass1234").hexdigest(),
    "client2": hashlib.sha256(b"secure99").hexdigest(),
    "admin"  : hashlib.sha256(b"admin123").hexdigest(),
}

# ── Logging ───────────────────────────────────────────────
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger("SERVER")


def audit(user, addr, cmd, status):
    log.info(f"AUDIT | user={user} ip={addr[0]}:{addr[1]} cmd={repr(cmd)} status={status}")


# ── Message helpers ───────────────────────────────────────
def send_msg(sock, data: dict):
    raw    = json.dumps(data).encode()
    length = len(raw).to_bytes(4, "big")
    sock.sendall(length + raw)

def recv_msg(sock) -> dict:
    def exact(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Client disconnected")
            buf += chunk
        return buf
    length = int.from_bytes(exact(4), "big")
    return json.loads(exact(length))


# ── Command execution ─────────────────────────────────────
def run_command(cmd: str) -> dict:
    parts   = cmd.strip().split()
    base    = parts[0] if parts else ""
    if base not in ALLOWED:
        return {"out": "", "err": f"'{base}' not allowed. Allowed: {sorted(ALLOWED)}", "code": 403}
    try:
        r = subprocess.run(parts, capture_output=True, text=True, timeout=10)
        return {"out": r.stdout, "err": r.stderr, "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"out": "", "err": "Timed out (10 s)", "code": -1}
    except Exception as e:
        return {"out": "", "err": str(e), "code": -2}


# ── Client handler ────────────────────────────────────────
def handle_client(conn, addr):
    user = "unknown"
    log.info(f"[+] New connection from {addr[0]}:{addr[1]}")
    try:
        # ── Step 1: Authentication ─────────────────────────
        send_msg(conn, {"type": "auth_request", "msg": "Send credentials"})
        creds = recv_msg(conn)
        user  = creds.get("username", "")
        pw_hash = hashlib.sha256(creds.get("password", "").encode()).hexdigest()

        if USERS.get(user) != pw_hash:
            send_msg(conn, {"type": "auth_fail", "msg": "Invalid username or password"})
            audit(user, addr, "LOGIN", "FAIL")
            log.warning(f"[-] Auth failed for '{user}' from {addr}")
            return

        send_msg(conn, {"type": "auth_ok", "msg": f"Welcome {user}! Type a command."})
        audit(user, addr, "LOGIN", "SUCCESS")
        log.info(f"[✓] Authenticated: {user} from {addr}")

        # ── Step 2: Command loop ───────────────────────────
        while True:
            req = recv_msg(conn)
            if req.get("type") == "disconnect":
                log.info(f"[~] {user} disconnected gracefully")
                audit(user, addr, "DISCONNECT", "OK")
                break

            cmd = req.get("command", "").strip()
            if not cmd:
                send_msg(conn, {"type": "result", "out": "", "err": "Empty command", "code": -1})
                continue

            log.info(f"[→] {user} @ {addr[0]}  cmd: {repr(cmd)}")
            result = run_command(cmd)
            send_msg(conn, {"type": "result", **result})
            audit(user, addr, cmd, f"code={result['code']}")

    except (ConnectionError, json.JSONDecodeError) as e:
        log.warning(f"[!] Connection error ({user} @ {addr}): {e}")
        audit(user, addr, "SESSION", f"ERROR: {e}")
    finally:
        conn.close()
        log.info(f"[-] Closed connection: {user} @ {addr}")


# ── Main ──────────────────────────────────────────────────
def main():
    # Wrap server socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))
    raw_sock.listen(10)

    server_sock = context.wrap_socket(raw_sock, server_side=True)
    log.info(f"[*] Secure RCE Server listening on {HOST}:{PORT}  (TLS enabled)")
    log.info(f"[*] Audit log → {LOG_FILE}")
    log.info(f"[*] Allowed commands: {sorted(ALLOWED)}\n")

    while True:
        try:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
            log.info(f"[*] Active threads: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            log.info("\n[*] Server shutting down.")
            break
        except ssl.SSLError as e:
            log.error(f"[!] SSL error on accept: {e}")

    server_sock.close()


if __name__ == "__main__":
    main()
