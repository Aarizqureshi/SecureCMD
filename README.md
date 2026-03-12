# Secure Remote Command Execution System

A client-server system where authenticated clients connect over a **TLS-encrypted TCP socket** and remotely execute shell commands on the server. The server responds with the command output.

```
[client1 — guest]    ──TLS──┐
                             ├──► server ──► shell ──► response
[client2 — operator] ──TLS──┤
                             │
[admin]              ──TLS──┘
```

---

## Project Structure

```
secure_rce/
├── server.py          # Async TLS server
├── client.py          # Async TLS client
├── certs/
│   ├── server.crt     # Self-signed TLS certificate
│   └── server.key     # Private key
└── logs/
    └── audit.log      # Audit trail (auto-created)
```

---

## Setup & Run

### Step 1 — Generate TLS Certificate (one-time)
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
  -out certs/server.crt -days 365 -nodes \
  -subj "/CN=localhost/O=SecureRCE/C=IN"
```

### Step 2 — Start the Server
```bash
python server.py
```

### Step 3 — Connect a Client
```bash
python client.py

# Or with explicit host/port
python client.py --host 127.0.0.1 --port 9999
```

---

## Users & Roles

| Username | Password  | Role     |
|----------|-----------|----------|
| client1  | pass1234  | guest    |
| client2  | secure99  | operator |
| admin    | admin123  | admin    |

Each role gets a different set of allowed commands and access levels.

---

## Roles & Permissions

### guest
Read-only access. File paths restricted to `/tmp`.
```
whoami  date  uptime  hostname  uname  echo  id  pwd
ls  cat  head  tail
```

### operator
Broader read access across the full filesystem.
```
whoami  date  uptime  hostname  uname  echo  id  pwd
env  df  ps  ls  cat  head  tail  wc  grep
```

### admin
Full access to all allowed commands.
```
whoami  date  uptime  hostname  uname  echo  id  pwd
env  df  ps  ls  cat  head  tail  wc  grep  find
```

Any command not in the list is **rejected with code 403**.

---

## Argument Sandboxing

Beyond the command whitelist, arguments are also validated before execution:

- **Flags** — each command has an allowed set of flags. Anything outside it is rejected.
  - e.g. `uname -z` → blocked for guest, `uname -a` → allowed
- **Paths** — file path arguments must resolve within the role's allowed prefix.
  - e.g. `cat /etc/passwd` → blocked for guest (outside `/tmp`)
  - Symlinks are resolved with `os.path.realpath()` before the check

---

## Authentication & Rate Limiting

Auth flow on every new connection:

```
client                              server
  |── TLS handshake ──────────────► |
  |◄── { auth_request } ─────────── |
  |── { username, password } ──────► |   (SHA-256 compared)
  |◄── { auth_ok, role, commands } ── |
  |── { command: "whoami" } ────────► |
  |◄── { out, err, code } ─────────── |
  |── { disconnect } ───────────────► |
```

**Rate limiting:** 5 consecutive failed logins from the same IP triggers a 30-second ban. The ban is checked before credentials are even requested.

---

## Message Protocol

All messages use a **4-byte big-endian length prefix** followed by a UTF-8 JSON payload.

```
[ 4 bytes — message length ][ JSON payload ]
```

Messages larger than **64 KB** are rejected immediately before any memory is allocated.

| Direction | `type`        | Key fields                    | Description                        |
|-----------|---------------|-------------------------------|------------------------------------|
| S → C     | auth_request  | msg                           | Server prompts for credentials     |
| C → S     | auth          | username, password            | Client sends credentials           |
| S → C     | auth_ok       | msg, role, allowed_commands   | Auth success with role info        |
| S → C     | auth_fail     | msg                           | Auth failure or IP ban             |
| C → S     | command       | command                       | Shell command string               |
| S → C     | result        | out, err, code                | stdout, stderr, exit code          |
| C → S     | disconnect    | —                             | Clean disconnect                   |

---

## Audit Log

Every event is written as a JSON line to `logs/audit.log`.

```json
{"ts":"2026-03-12T10:00:01Z","user":"client1","ip":"127.0.0.1","action":"LOGIN","detail":"role=guest","status":"SUCCESS"}
{"ts":"2026-03-12T10:00:03Z","user":"client1","ip":"127.0.0.1","action":"CMD","detail":"whoami","status":"code=0"}
{"ts":"2026-03-12T10:00:05Z","user":"client1","ip":"127.0.0.1","action":"CMD","detail":"cat /etc/passwd","status":"code=403"}
{"ts":"2026-03-12T10:00:10Z","user":"client1","ip":"127.0.0.1","action":"DISCONNECT","detail":"","status":"OK"}
{"ts":"2026-03-12T10:01:00Z","user":"hacker","ip":"127.0.0.1","action":"LOGIN","detail":"","status":"FAIL"}
```

---

## Example Session

```
[*] Connecting to 127.0.0.1:9999 (TLS) ...
[✓] TLS connected  |  cipher: TLS_AES_256_GCM_SHA384

[server] Send credentials
Username: client1
Password: ****
[✓] Welcome client1! Role: guest. Type a command.
    Role     : guest
    Commands : cat, date, echo, head, hostname, id, ls, pwd, tail, uname, uptime, whoami

client1(guest)@remote> whoami
root

client1(guest)@remote> cat /etc/passwd
[stderr] Path '/etc/passwd' is outside allowed prefix '/tmp'.
[exit 403]

client1(guest)@remote> cat /tmp/notes.txt
hello from /tmp

client1(guest)@remote> exit
[*] Disconnected.
```

---

## Security Notes

- All traffic is TLS-encrypted — no plaintext on the wire
- Passwords are compared as SHA-256 hashes
- Commands and arguments are both validated before any execution
- Symlink traversal is blocked via `os.path.realpath()`
- Oversized messages are dropped before memory allocation
- Brute-force is slowed by IP lockout after 5 failed attempts
