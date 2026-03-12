"""
=============================================================
 Secure Remote Command Execution System  ─  CLIENT
 Project  : Jackfruit Mini Project  (Deliverable 1)
 Language : Python 3
=============================================================
Usage:
    python client.py
    python client.py --host 127.0.0.1 --port 9999
=============================================================
"""

import socket, ssl, json, argparse, getpass

# ── Config ────────────────────────────────────────────────
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
CA_CERT      = "certs/server.crt"   # self-signed → use as CA


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
                raise ConnectionError("Server closed connection")
            buf += chunk
        return buf
    length = int.from_bytes(exact(4), "big")
    return json.loads(exact(length))


# ── Pretty print result ───────────────────────────────────
def print_result(res: dict):
    code = res.get("code", "?")
    out  = res.get("out", "").strip()
    err  = res.get("err", "").strip()

    if out:
        print(out)
    if err:
        print(f"\033[91m[stderr] {err}\033[0m")   # red
    if code not in (0, "?"):
        print(f"\033[93m[exit code: {code}]\033[0m")   # yellow


# ── Main ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Secure RCE Client")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    # SSL context: verify server cert against our CA cert
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(CA_CERT)
    context.check_hostname = False   # self-signed has no hostname

    print(f"[*] Connecting to {args.host}:{args.port} (TLS) ...")
    raw_sock = socket.create_connection((args.host, args.port))
    conn     = context.wrap_socket(raw_sock, server_hostname=args.host)
    print(f"[✓] TLS connected  |  cipher: {conn.cipher()[0]}\n")

    try:
        # ── Auth handshake ─────────────────────────────────
        msg = recv_msg(conn)
        print(f"[server] {msg.get('msg')}")

        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        send_msg(conn, {"type": "auth", "username": username, "password": password})

        resp = recv_msg(conn)
        if resp.get("type") == "auth_fail":
            print(f"\033[91m[✗] Auth failed: {resp.get('msg')}\033[0m")
            return
        print(f"\033[92m[✓] {resp.get('msg')}\033[0m\n")

        # ── Command shell ──────────────────────────────────
        print("Type commands to run on the server. Type 'exit' to quit.\n")
        while True:
            try:
                cmd = input(f"\033[96m{username}@remote>\033[0m ").strip()
            except (EOFError, KeyboardInterrupt):
                cmd = "exit"

            if cmd.lower() in ("exit", "quit", "q"):
                send_msg(conn, {"type": "disconnect"})
                print("[*] Disconnected.")
                break

            if not cmd:
                continue

            send_msg(conn, {"type": "command", "command": cmd})
            result = recv_msg(conn)
            print_result(result)

    except ConnectionError as e:
        print(f"\033[91m[!] Connection lost: {e}\033[0m")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
