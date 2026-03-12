"""
=============================================================
 Secure Remote Command Execution System  ─  SERVER v2
 Project  : Jackfruit Mini Project  (Deliverable 2)
 Language : Python 3 (asyncio — no threads)
=============================================================
Upgrades over v1
  [1] asyncio  ─ proper I/O multiplexing (no threads)
  [2] Role-based access control  ─ admin > operator > guest
  [3] Auth rate-limiting + IP lockout (5 fails → 30 s ban)
  [4] Argument sandboxing  ─ per-command path/flag whitelist
  [5] Max message size guard  ─ prevents memory exhaustion
  [6] Structured audit log  ─ JSON lines for easy parsing
=============================================================
Syllabus mapping
  asyncio          → Transport Layer: Multiplexing/Demultiplexing
  TLS wrap         → HTTPS / Transport Layer Security
  client-server    → Network Application Architectures
  length-prefix    → Reliable Data Transfer (framing)
  rate limiting    → Application Layer protocol design
  role-based cmds  → Transport Services available to Applications
=============================================================
"""

import asyncio, ssl, json, subprocess, hashlib
import logging, time, os
from pathlib import Path
from collections import defaultdict

# ── Config ────────────────────────────────────────────────
HOST      = "0.0.0.0"
PORT      = 9999
CERT_FILE = "certs/server.crt"
KEY_FILE  = "certs/server.key"
LOG_FILE  = "logs/audit.log"

MAX_MSG_BYTES  = 64 * 1024      # 64 KB max per message  [upgrade 5]
AUTH_FAIL_MAX  = 5              # lockout after N failures [upgrade 3]
LOCKOUT_SECS   = 30             # ban duration in seconds

# ── Role-based command whitelist  [upgrade 2 + 4] ─────────
#
# Structure:
#   ROLES[role] = {
#       "command": {"allowed_flags": [...], "allowed_path_prefix": "..."}
#   }
#
# allowed_flags  : set of flag strings the user may pass
# allowed_path_prefix : if present, path args must start with this
# (None means no path restriction for that command)

ROLES = {
    # ── guest: read-only, no path traversal ───────────────
    "guest": {
        "whoami":   {},
        "date":     {},
        "uptime":   {},
        "hostname": {},
        "uname":    {"allowed_flags": {"-a", "-r", "-n"}},
        "echo":     {},
        "id":       {},
        "pwd":      {},
        "ls":       {"allowed_flags": {"-l", "-a", "-la", "-al", "-lh"},
                     "allowed_path_prefix": "/tmp"},
        "cat":      {"allowed_path_prefix": "/tmp"},
        "head":     {"allowed_path_prefix": "/tmp"},
        "tail":     {"allowed_path_prefix": "/tmp"},
    },

    # ── operator: wider read access ───────────────────────
    "operator": {
        "whoami":   {},
        "date":     {},
        "uptime":   {},
        "hostname": {},
        "uname":    {"allowed_flags": {"-a", "-r", "-n", "-m", "-s"}},
        "echo":     {},
        "id":       {},
        "pwd":      {},
        "env":      {},
        "df":       {"allowed_flags": {"-h", "-H", "--human-readable"}},
        "ps":       {"allowed_flags": {"-e", "-f", "-ef", "aux", "-aux"}},
        "ls":       {"allowed_flags": {"-l", "-a", "-la", "-al", "-lh", "-R"}},
        "cat":      {"allowed_path_prefix": "/"},
        "head":     {"allowed_path_prefix": "/"},
        "tail":     {"allowed_flags": {"-n", "-f", "-F"},
                     "allowed_path_prefix": "/"},
        "wc":       {"allowed_flags": {"-l", "-w", "-c"}},
        "grep":     {"allowed_flags": {"-i", "-r", "-n", "-l", "-v", "-c"}},
    },

    # ── admin: full whitelist, no path restriction ─────────
    "admin": {
        "whoami":   {},
        "date":     {},
        "uptime":   {},
        "hostname": {},
        "uname":    {},
        "echo":     {},
        "id":       {},
        "pwd":      {},
        "env":      {},
        "df":       {},
        "ps":       {},
        "ls":       {},
        "cat":      {},
        "head":     {},
        "tail":     {},
        "wc":       {},
        "grep":     {},
        "find":     {"allowed_path_prefix": "/tmp"},
    },
}

# ── User DB  { username: (sha256_hash, role) } ────────────
def _h(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

USERS = {
    "client1": (_h("pass1234"), "guest"),
    "client2": (_h("secure99"), "operator"),
    "admin"  : (_h("admin123"), "admin"),
}

# ── Logging ───────────────────────────────────────────────
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("SRV")

def audit(user: str, ip: str, action: str, detail: str, status: str):
    """Write a structured JSON audit line."""
    entry = json.dumps({
        "ts":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user":   user,
        "ip":     ip,
        "action": action,
        "detail": detail,
        "status": status,
    })
    log.info(f"AUDIT {entry}")


# ── Rate limiter (in-memory)  [upgrade 3] ─────────────────
_fail_counts: dict[str, int]   = defaultdict(int)
_lockout_until: dict[str, float] = {}

def check_lockout(ip: str) -> float:
    """Return remaining ban seconds, or 0 if clear."""
    until = _lockout_until.get(ip, 0)
    remaining = until - time.monotonic()
    return remaining if remaining > 0 else 0

def record_fail(ip: str):
    _fail_counts[ip] += 1
    if _fail_counts[ip] >= AUTH_FAIL_MAX:
        _lockout_until[ip] = time.monotonic() + LOCKOUT_SECS
        _fail_counts[ip] = 0
        log.warning(f"[!] IP {ip} locked out for {LOCKOUT_SECS}s")

def record_success(ip: str):
    _fail_counts[ip] = 0
    _lockout_until.pop(ip, None)


# ── Message helpers (async)  [upgrade 1] ──────────────────
async def send_msg(writer: asyncio.StreamWriter, data: dict):
    raw    = json.dumps(data).encode()
    length = len(raw).to_bytes(4, "big")
    writer.write(length + raw)
    await writer.drain()

async def recv_msg(reader: asyncio.StreamReader) -> dict:
    hdr = await reader.readexactly(4)
    length = int.from_bytes(hdr, "big")

    # [upgrade 5] guard against memory exhaustion
    if length > MAX_MSG_BYTES:
        raise ValueError(f"Message too large: {length} bytes (max {MAX_MSG_BYTES})")

    raw = await reader.readexactly(length)
    return json.loads(raw)


# ── Argument sandboxing  [upgrade 4] ──────────────────────
def validate_args(base: str, parts: list[str], role_cmds: dict) -> str | None:
    """
    Check all arguments against per-command rules.
    Returns an error string if rejected, or None if OK.
    """
    rules = role_cmds.get(base, None)
    if rules is None:
        return f"'{base}' not allowed for your role."

    allowed_flags  = rules.get("allowed_flags", None)   # None = any flag OK
    path_prefix    = rules.get("allowed_path_prefix", None)

    for arg in parts[1:]:
        if arg.startswith("-"):
            # It's a flag
            if allowed_flags is not None and arg not in allowed_flags:
                return f"Flag '{arg}' not allowed for '{base}'."
        else:
            # It's a path / value argument
            if path_prefix is not None:
                real = os.path.realpath(arg)  # resolve symlinks
                if not real.startswith(path_prefix):
                    return (
                        f"Path '{arg}' is outside allowed prefix "
                        f"'{path_prefix}'."
                    )
    return None  # all good


# ── Command execution ─────────────────────────────────────
def run_command(cmd: str, role: str) -> dict:
    parts = cmd.strip().split()
    if not parts:
        return {"out": "", "err": "Empty command.", "code": -1}

    base       = parts[0]
    role_cmds  = ROLES.get(role, {})

    # Check base command allowed for role
    if base not in role_cmds:
        allowed = sorted(role_cmds.keys())
        return {
            "out": "",
            "err": f"'{base}' not allowed for role '{role}'. Allowed: {allowed}",
            "code": 403,
        }

    # Validate arguments
    err = validate_args(base, parts, role_cmds)
    if err:
        return {"out": "", "err": err, "code": 403}

    # Execute
    try:
        r = subprocess.run(
            parts, capture_output=True, text=True, timeout=10
        )
        return {"out": r.stdout, "err": r.stderr, "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"out": "", "err": "Command timed out (10 s).", "code": -1}
    except Exception as e:
        return {"out": "", "err": str(e), "code": -2}


# ── Client handler (coroutine)  [upgrade 1] ───────────────
async def handle_client(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    ip   = addr[0] if addr else "unknown"
    user = "unknown"
    role = "none"

    log.info(f"[+] Connection from {ip}:{addr[1]}")

    try:
        # ── Lockout check  [upgrade 3] ────────────────────
        ban = check_lockout(ip)
        if ban > 0:
            await send_msg(writer, {
                "type": "auth_fail",
                "msg":  f"IP banned. Try again in {ban:.0f}s.",
            })
            log.warning(f"[!] Rejected banned IP {ip}")
            return

        # ── Auth handshake ────────────────────────────────
        await send_msg(writer, {"type": "auth_request", "msg": "Send credentials"})
        creds   = await recv_msg(reader)
        user    = creds.get("username", "")
        pw_hash = hashlib.sha256(creds.get("password", "").encode()).hexdigest()

        stored  = USERS.get(user)
        if not stored or stored[0] != pw_hash:
            await send_msg(writer, {"type": "auth_fail", "msg": "Invalid credentials."})
            record_fail(ip)
            audit(user, ip, "LOGIN", "", "FAIL")
            fails = _fail_counts[ip]
            log.warning(f"[-] Auth fail #{fails} for '{user}' from {ip}")
            return

        role = stored[1]
        record_success(ip)
        await send_msg(writer, {
            "type": "auth_ok",
            "msg":  f"Welcome {user}! Role: {role}. Type a command.",
            "role": role,
            "allowed_commands": sorted(ROLES[role].keys()),
        })
        audit(user, ip, "LOGIN", f"role={role}", "SUCCESS")
        log.info(f"[✓] {user} ({role}) authenticated from {ip}")

        # ── Command loop ──────────────────────────────────
        while True:
            req = await recv_msg(reader)

            if req.get("type") == "disconnect":
                audit(user, ip, "DISCONNECT", "", "OK")
                log.info(f"[~] {user} disconnected")
                break

            cmd = req.get("command", "").strip()
            if not cmd:
                await send_msg(writer, {
                    "type": "result", "out": "", "err": "Empty command.", "code": -1
                })
                continue

            result = run_command(cmd, role)
            await send_msg(writer, {"type": "result", **result})
            audit(user, ip, "CMD", cmd, f"code={result['code']}")
            log.info(f"[→] {user}({role}) cmd={repr(cmd)} code={result['code']}")

    except asyncio.IncompleteReadError:
        log.info(f"[~] {user} @ {ip} disconnected (EOF)")
    except ValueError as e:
        log.warning(f"[!] Protocol error from {ip}: {e}")
        audit(user, ip, "PROTO_ERR", str(e), "ERROR")
    except json.JSONDecodeError as e:
        log.warning(f"[!] Bad JSON from {ip}: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        log.info(f"[-] Closed: {user} @ {ip}")


# ── Main ──────────────────────────────────────────────────
async def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    server = await asyncio.start_server(
        handle_client, HOST, PORT, ssl=context
    )

    log.info(f"[*] Secure RCE Server v2  listening on {HOST}:{PORT}  (asyncio + TLS)")
    log.info(f"[*] Roles: {list(ROLES.keys())}")
    log.info(f"[*] Audit log → {LOG_FILE}\n")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("\n[*] Server shut down.")
