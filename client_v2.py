"""
=============================================================
 Secure Remote Command Execution System  ─  CLIENT v2
 Project  : Jackfruit Mini Project  (Deliverable 2)
 Language : Python 3 (asyncio)
=============================================================
Usage:
    python client.py
    python client.py --host 127.0.0.1 --port 9999
=============================================================
"""

import asyncio, ssl, json, argparse, getpass, sys

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
CA_CERT      = "certs/server.crt"
MAX_MSG_BYTES = 64 * 1024


# ── Message helpers (async) ───────────────────────────────
async def send_msg(writer: asyncio.StreamWriter, data: dict):
    raw    = json.dumps(data).encode()
    length = len(raw).to_bytes(4, "big")
    writer.write(length + raw)
    await writer.drain()

async def recv_msg(reader: asyncio.StreamReader) -> dict:
    hdr    = await reader.readexactly(4)
    length = int.from_bytes(hdr, "big")
    if length > MAX_MSG_BYTES:
        raise ValueError(f"Server sent oversized message ({length} bytes)")
    raw = await reader.readexactly(length)
    return json.loads(raw)


# ── Pretty print result ───────────────────────────────────
def print_result(res: dict):
    out  = res.get("out", "").rstrip()
    err  = res.get("err", "").rstrip()
    code = res.get("code", "?")

    if out:
        print(out)
    if err:
        print(f"\033[91m[stderr] {err}\033[0m")
    if code not in (0, "?"):
        print(f"\033[93m[exit {code}]\033[0m")


# ── Main coroutine ────────────────────────────────────────
async def run(host: str, port: int):
    # TLS context: verify server cert
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(CA_CERT)
    context.check_hostname = False   # self-signed cert

    print(f"[*] Connecting to {host}:{port} (TLS) ...")
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=context)
    except Exception as e:
        print(f"\033[91m[✗] Could not connect: {e}\033[0m")
        return

    cipher = writer.get_extra_info("ssl_object").cipher()[0]
    print(f"[✓] TLS connected  |  cipher: {cipher}\n")

    try:
        # ── Auth ───────────────────────────────────────────
        msg = await recv_msg(reader)
        print(f"[server] {msg.get('msg')}")

        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        await send_msg(writer, {"type": "auth", "username": username, "password": password})

        resp = await recv_msg(reader)
        if resp.get("type") == "auth_fail":
            print(f"\033[91m[✗] {resp.get('msg')}\033[0m")
            return

        print(f"\033[92m[✓] {resp.get('msg')}\033[0m")
        role    = resp.get("role", "?")
        allowed = resp.get("allowed_commands", [])
        print(f"    Role     : \033[96m{role}\033[0m")
        print(f"    Commands : {', '.join(allowed)}\n")

        # ── Command shell ──────────────────────────────────
        loop = asyncio.get_event_loop()
        while True:
            try:
                # read input in executor so asyncio loop stays alive
                prompt = f"\033[96m{username}({role})@remote>\033[0m "
                cmd = await loop.run_in_executor(
                    None, lambda: input(prompt).strip()
                )
            except (EOFError, KeyboardInterrupt):
                cmd = "exit"

            if cmd.lower() in ("exit", "quit", "q"):
                await send_msg(writer, {"type": "disconnect"})
                print("[*] Disconnected.")
                break

            if not cmd:
                continue

            # client-side help shortcut
            if cmd == "help":
                print(f"Allowed commands for role '{role}': {', '.join(allowed)}")
                continue

            await send_msg(writer, {"type": "command", "command": cmd})
            result = await recv_msg(reader)
            print_result(result)

    except asyncio.IncompleteReadError:
        print("\033[91m[!] Server closed connection.\033[0m")
    except ValueError as e:
        print(f"\033[91m[!] Protocol error: {e}\033[0m")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ── Entry point ───────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Secure RCE Client v2")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    asyncio.run(run(args.host, args.port))

if __name__ == "__main__":
    main()
