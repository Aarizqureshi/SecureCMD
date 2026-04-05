"""
=============================================================
 Secure Remote Command Execution System  ─  SERVER v2
 Project  : Jackfruit Mini Project  (Deliverable 2)
 Language : Python 3 (asyncio — no threads)
 Platform : Windows (adapted)
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
import logging, time, os, sys
from pathlib import Path
from collections import defaultdict

# ── Windows asyncio fix ───────────────────────────────────
# On Windows, the default ProactorEventLoop does not support
# SSL with asyncio.start_server; SelectorEventLoop is required.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ── Config ────────────────────────────────────────────────
HOST      = "0.0.0.0"
PORT      = 9999
CERT_FILE   = "certs/server.crt"
KEY_FILE    = "certs/server.key"
CA_CERT     = "certs/ca.crt"          # CA that signs client certificates
CLIENT_CERT = "certs/client.crt"      # client's own certificate (client-side)
CLIENT_KEY  = "certs/client.key"      # client's private key    (client-side)
LOG_FILE    = "logs/audit.log"

MAX_MSG_BYTES  = 64 * 1024      # 64 KB max per message  [upgrade 5]
AUTH_FAIL_MAX  = 5              # lockout after N failures [upgrade 3]
LOCKOUT_SECS   = 30             # ban duration in seconds

# ── Role-based command whitelist  [upgrade 2 + 4] ─────────
#
# Windows-native commands replace Linux ones.
# Structure:
#   ROLES[role] = {
#       "command": {"allowed_flags": [...], "allowed_path_prefix": "..."}
#   }
#
# allowed_flags       : set of flag strings the user may pass
# allowed_path_prefix : if present, path args must start with this
# (None means no path restriction for that command)

ROLES = {
    # ── guest: read-only, safe info only ──────────────────
    "guest": {
        "whoami":    {},
        "hostname":  {},
        "echo":      {},
        "date":      {},        # prints current date  (cmd /c date /t)
        "time":      {},        # prints current time  (cmd /c time /t)
        "ver":       {},        # Windows version
        "dir":       {"allowed_flags": {"/b", "/w", "/p"},
                      "allowed_path_prefix": "C:\\Temp"},
        "type":      {"allowed_path_prefix": "C:\\Temp"},
        "findstr":   {"allowed_flags": {"/i", "/n", "/c"},
                      "allowed_path_prefix": "C:\\Temp"},
    },

    # ── operator: wider read access ───────────────────────
    "operator": {
        "whoami":    {},
        "hostname":  {},
        "echo":      {},
        "date":      {},
        "time":      {},
        "ver":       {},
        "ipconfig":  {"allowed_flags": {"/all"}},
        "tasklist":  {"allowed_flags": {"/v", "/fo", "TABLE", "CSV", "LIST"}},
        "systeminfo":{},
        "netstat":   {"allowed_flags": {"-a", "-n", "-o", "-an", "-ano"}},
        "dir":       {"allowed_flags": {"/b", "/w", "/p", "/s", "/a"},
                      "allowed_path_prefix": "C:\\"},
        "type":      {"allowed_path_prefix": "C:\\"},
        "findstr":   {"allowed_flags": {"/i", "/r", "/n", "/l", "/v", "/c", "/s"}},
        "wmic":      {"allowed_flags": {"cpu", "os", "computersystem",
                                        "get", "list", "brief"}},
    },

    # ── admin: full whitelist ─────────────────────────────
    "admin": {
        "whoami":    {},
        "hostname":  {},
        "echo":      {},
        "date":      {},
        "time":      {},
        "ver":       {},
        "ipconfig":  {},
        "tasklist":  {},
        "systeminfo":{},
        "netstat":   {},
        "dir":       {},
        "type":      {},
        "findstr":   {},
        "wmic":      {},
        "net":       {"allowed_flags": {"user", "localgroup", "share",
                                        "use", "view", "start", "stop"}},
        "ping":      {"allowed_flags": {"-n", "-l", "-w", "-4", "-6"}},
        "tracert":   {"allowed_flags": {"-d", "-h", "-w", "-4", "-6"}},
    },
}

# ── User DB  { username: (sha256_hash, role) } ────────────
#
# Credentials are loaded from users.json — NOT hardcoded here.
# Format of users.json:
#   {
#     "client1": {"password_sha256": "<hex>", "role": "guest"},
#     "admin":   {"password_sha256": "<hex>", "role": "admin"}
#   }
#
# To generate a hash for a new password, run:
#   python -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"
#
USERS_FILE = "users.json"

def _load_users(path: str) -> dict:
    """Load user credentials from a JSON file.  Aborts if file is missing."""
    p = Path(path)
    if not p.exists():
        # Create a template file and exit — never fall back to defaults.
        template = {
            "client1": {
                "password_sha256": "REPLACE_WITH_SHA256_HASH",
                "role": "guest"
            },
            "client2": {
                "password_sha256": "REPLACE_WITH_SHA256_HASH",
                "role": "operator"
            },
            "admin": {
                "password_sha256": "REPLACE_WITH_SHA256_HASH",
                "role": "admin"
            },
        }
        p.write_text(json.dumps(template, indent=2), encoding="utf-8")
        print(f"[!] '{path}' not found — a template has been created.")
        print( "    Fill in the password_sha256 fields, then restart the server.")
        print( "    Generate a hash:  python -c \"import hashlib; print(hashlib.sha256(b'pw').hexdigest())\"")
        sys.exit(1)

    raw = json.loads(p.read_text(encoding="utf-8"))
    users = {}
    for username, entry in raw.items():
        h    = entry.get("password_sha256", "")
        role = entry.get("role", "guest")
        if h == "REPLACE_WITH_SHA256_HASH" or not h:
            print(f"[!] User '{username}' in {path} has no valid password hash — skipping.")
            continue
        if role not in ROLES:
            print(f"[!] User '{username}' has unknown role '{role}' — skipping.")
            continue
        users[username] = (h, role)
    if not users:
        print(f"[!] No valid users found in '{path}'. Aborting.")
        sys.exit(1)
    return users

USERS: dict = {}   # populated in main() after ROLES is defined

# ── Logging ───────────────────────────────────────────────
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
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
_fail_counts:   dict[str, int]   = defaultdict(int)
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
    hdr    = await reader.readexactly(4)
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

    allowed_flags = rules.get("allowed_flags", None)   # None = any flag OK
    path_prefix   = rules.get("allowed_path_prefix", None)

    for arg in parts[1:]:
        if arg.startswith("/") or arg.startswith("-"):
            # It's a flag / switch
            if allowed_flags is not None and arg not in allowed_flags:
                return f"Flag '{arg}' not allowed for '{base}'."
        else:
            # It's a path / value argument
            if path_prefix is not None:
                # Resolve real path to prevent traversal attacks
                try:
                    real = str(Path(arg).resolve())
                except Exception:
                    return f"Invalid path argument: '{arg}'."
                if not real.lower().startswith(path_prefix.lower()):
                    return (
                        f"Path '{arg}' is outside allowed prefix "
                        f"'{path_prefix}'."
                    )
    return None  # all good


# ── Windows command execution ─────────────────────────────
# Many Windows built-in commands (date, time, dir, etc.) are
# shell built-ins and must be run via cmd.exe /c.
SHELL_BUILTINS = {
    "date", "time", "dir", "ver", "echo", "type",
    "findstr", "net", "ipconfig", "tasklist",
    "systeminfo", "netstat", "wmic", "ping",
    "tracert", "whoami", "hostname",
}

def run_command(cmd: str, role: str) -> dict:
    parts     = cmd.strip().split()
    if not parts:
        return {"out": "", "err": "Empty command.", "code": -1}

    base      = parts[0].lower()
    role_cmds = ROLES.get(role, {})
<<<<<<< HEAD

    # Force non-interactive mode for date/time — without /t they open
    # an interactive prompt and hang the subprocess forever.
    if base in ("date", "time") and "/t" not in [p.lower() for p in parts[1:]]:
        parts.append("/t")
        cmd = " ".join(parts)
=======
>>>>>>> fc9043ac4fa2750f376cf35dc326e33f35051a24

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

    # Execute via cmd.exe shell for built-ins; direct otherwise
    try:
        use_shell = base in SHELL_BUILTINS
        r = subprocess.run(
            cmd if use_shell else parts,
            shell=use_shell,
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
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

        stored = USERS.get(user)
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
    global USERS
    USERS = _load_users(USERS_FILE)
    log.info(f"[*] Loaded {len(USERS)} user(s) from {USERS_FILE}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    # ── Mutual TLS: require a valid client certificate ────
    # CERT_REQUIRED means the TLS handshake fails immediately if the
    # client cannot present a certificate signed by CA_CERT.
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(CA_CERT)

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
