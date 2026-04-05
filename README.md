# Secure Remote Command Execution System — v2
**Jackfruit Mini Project · Deliverable 2 · Windows Edition**

A role-based remote command shell secured with TLS and **mutual TLS (mTLS)** authentication, built entirely on Python's standard library. A single server accepts multiple simultaneous clients using asyncio — no threads required. Each client authenticates with a username and password, receives a role, and can only execute the commands that role permits. All traffic is encrypted end-to-end.

> **What's new in v2:** Passwords moved out of source code into `users.json` (hashes only). Mutual TLS added — the server rejects unknown machines at the handshake level before any Python code runs. `date` and `time` commands now work correctly.

---

## Table of Contents

1. [How It Works](#1-how-it-works)
2. [Prerequisites](#2-prerequisites)
3. [Folder Structure](#3-folder-structure)
4. [Server Setup](#4-server-setup-step-by-step)
5. [Client Setup](#5-client-setup-step-by-step)
6. [Using the Shell](#6-using-the-shell)
7. [Credentials & Roles](#7-credentials--roles)
8. [Troubleshooting](#8-troubleshooting)
9. [Security Notes](#9-security-notes)
10. [Audit Log Reference](#10-audit-log-reference)
11. [Quick Reference Card](#11-quick-reference-card)

---

## 1. How It Works

### 1.1 Architecture Overview

```
  CLIENT A ──┐
             ├──(mTLS/TCP)──► SERVER (asyncio, single thread)
  CLIENT B ──┘                    │
                                  ├─ TLS handshake: verify client cert
                                  ├─ authenticate username + password
                                  ├─ check role & command whitelist
                                  ├─ run command via subprocess
                                  └─ stream result back (length-prefix JSON)
```

The server runs a single asyncio event loop. Each connected client gets its own `handle_client` coroutine. While one client waits on I/O, the loop services others — no threads needed. There is no hard cap on concurrent clients; the OS socket limit applies (typically ~65 000), but in practice CPU and memory are the real constraint.

---

### 1.2 TLS & Mutual TLS

The server wraps its TCP socket with TLS. In v2 this is **mutual TLS (mTLS)**: both sides present a certificate signed by a shared Certificate Authority (CA).

| Side | Presents | Verifies |
|------|----------|----------|
| Server | `server.crt` | Client cert signed by `ca.crt` |
| Client | `client.crt` | Server cert signed by `ca.crt` |

A client without a valid certificate is **dropped at the TLS handshake** — before the authentication prompt, before any Python logic runs.

> **Self-signed CA:** Acceptable for a controlled lab. For production, use a CA-signed certificate and set `check_hostname = True` in the client.

---

### 1.3 Message Framing (Length-Prefix Protocol)

Every message — auth packets, commands, results — is sent as UTF-8 JSON with a **4-byte big-endian length header** prepended.

```
┌──────────────────────┬────────────────────────────────┐
│  4 bytes (length)    │  N bytes (JSON payload)        │
└──────────────────────┴────────────────────────────────┘
```

The receiver reads exactly 4 bytes, converts to an integer, then reads exactly that many bytes of JSON. Messages over 64 KB are rejected on both sides to prevent memory exhaustion.

---

### 1.4 Authentication & mTLS Flow

```
SERVER                                CLIENT
  │                                      │
  │◄──── TLS handshake (both certs) ────►│  ← mTLS: reject unknown machines here
  │                                      │
  │──── { type: "auth_request" } ───────►│
  │                                      │  (user types username + password)
  │◄─── { type: "auth", username, pw } ──│
  │                                      │
  │  [SHA-256 hash pw, compare to DB]    │
  │                                      │
  │──── { type: "auth_ok",  ────────────►│  ← includes role + allowed commands
  │      role, allowed_commands }         │
  │               OR                      │
  │──── { type: "auth_fail" } ───────────►│  ← failure counter incremented for IP
```

Passwords are **never stored in plain text** — only their SHA-256 hashes live in `users.json`.

---

### 1.5 Rate Limiting & IP Lockout

The server tracks authentication failures per IP address in memory.

| Setting | Value |
|---------|-------|
| Failures before lockout | 5 |
| Lockout duration | 30 seconds |
| Scope | Per connecting IP address |
| Reset on | Successful login |

A banned IP receives an immediate `auth_fail` and the connection is dropped before the handshake even starts.

> **Note:** Rate limiting is in-memory only. Restarting the server resets all failure counters and lockouts.

---

### 1.6 Role-Based Access Control (RBAC)

Three roles exist, each with a fixed whitelist of Windows commands. For every incoming command the server checks three things in order:

1. **Is the base command in this role's whitelist?** If not → `403`, not executed.
2. **Are all flags in the `allowed_flags` set for this command?** If not → `403`.
3. **If the command takes a path, does the resolved path start with `allowed_path_prefix`?** `Path.resolve()` is used to defeat `..` traversal tricks.

| Role | Allowed Commands | Path Restriction |
|------|-----------------|-----------------|
| `guest` | `whoami`, `hostname`, `echo`, `date`, `time`, `ver`, `dir`, `type`, `findstr` | `dir` / `type` / `findstr` → `C:\Temp` only |
| `operator` | All guest + `ipconfig`, `tasklist`, `systeminfo`, `netstat`, `wmic` | `dir` / `type` → anywhere under `C:\` |
| `admin` | All operator + `net`, `ping`, `tracert` | No path restriction |

---

### 1.7 date & time Fix

`date` and `time` are Windows shell built-ins that open an **interactive prompt** when called without `/t`, which hangs the subprocess forever. The server now automatically appends `/t` to these commands if the flag isn't already present — so typing `date` or `time` at the shell always returns output immediately.

---

### 1.8 Credential File (users.json)

Passwords are no longer hardcoded in `server_v2.py`. On startup the server loads `users.json`, which stores only SHA-256 hashes. If the file is missing, the server creates a template and exits with instructions. If a user entry still has the placeholder hash, that user is skipped and a warning is logged.

---

### 1.9 Windows Command Execution

Many Windows commands (`dir`, `echo`, `type`, `ver`, etc.) are shell built-ins inside `cmd.exe` — they cannot be launched as standalone executables. The server handles this:

```python
SHELL_BUILTINS = {"date", "time", "dir", "ver", "echo", "type", ...}

# shell built-ins  → run via cmd.exe
subprocess.run(cmd, shell=True, ...)

# standalone executables (ping, whoami, etc.) → direct launch, safer
subprocess.run(parts, shell=False, ...)
```

Both paths are still gated through the role whitelist before execution.

---

### 1.10 Audit Logging

Every significant event is written as a JSON line to `logs\audit.log` and mirrored to the console:

```json
{"ts":"2025-01-01T12:00:00Z","user":"client2","ip":"192.168.1.5","action":"CMD","detail":"ipconfig /all","status":"code=0"}
```

---

## 2. Prerequisites

Install the following on **all machines** before doing anything else.

| Requirement | Where Needed | Notes |
|-------------|-------------|-------|
| **Python 3.11+** | Server + all clients | [python.org/downloads](https://python.org/downloads) — tick **Add Python to PATH** during install |
| **OpenSSL** | Server only (cert generation) | Easiest via **Git for Windows** ([git-scm.com](https://git-scm.com)) — comes bundled |
| **`C:\Temp` folder** | Server only | Must exist for guest-role path restrictions |
| **No pip packages** | Both | Everything uses the Python standard library only |

**Verify Python is installed correctly** — open a new Command Prompt and run:

```cmd
python --version
# Expected: Python 3.11.x or higher
```

---

## 3. Folder Structure

### 3.1 Server Machine

```
project\
    server_v2.py
    users.json              ← credentials (SHA-256 hashes only, never plain text)
    gen_certs.sh            ← run once in Git Bash to create all certificates
    certs\
        ca.crt              ← Certificate Authority  (copy to every client)
        ca.key              ← CA private key         (server only — NEVER share)
        server.crt          ← Server certificate     (server only)
        server.key          ← Server private key     (server only — NEVER share)
        client.crt          ← Client certificate     (copy to every client)
        client.key          ← Client private key     (copy to every client)
    logs\                   ← created automatically on first server start
        audit.log
```

### 3.2 Each Client Machine

```
project\
    client_v2.py
    certs\
        ca.crt              ← copied from server
        client.crt          ← copied from server
        client.key          ← copied from server
```

> ⚠️ **Never copy `server.key` or `ca.key` to any client.** Only the three files listed above belong on the client side.

---

## 4. Server Setup (Step-by-Step)

### Step 1 — Create the project folders

Open **Command Prompt** and run:

```cmd
mkdir C:\project
mkdir C:\project\certs
mkdir C:\Temp
```

Copy `server_v2.py`, `users.json`, and `gen_certs.sh` into `C:\project\`.

---

### Step 2 — Generate all TLS certificates (mTLS setup)

Open **Git Bash** (right-click Start menu → Git Bash) and run:

```bash
cd /c/project
bash gen_certs.sh
```

This runs five OpenSSL commands and produces the following files in `certs\`:

| File | Purpose | Who Needs It |
|------|---------|-------------|
| `ca.crt` | Certificate Authority — the trust anchor | Server + every client |
| `ca.key` | CA private key — signs certificates | Server only — **NEVER share** |
| `server.crt` | Server's TLS certificate | Server only |
| `server.key` | Server's private key | Server only — **NEVER share** |
| `client.crt` | Client certificate presented during mTLS handshake | Every client |
| `client.key` | Client private key | Every client |

> **What mTLS adds over v1:** Previously only the client verified the server's identity. Now the server also demands a valid certificate from the client — signed by your CA. Any connection without a proper certificate is dropped before Python code runs.

---

### Step 3 — Set up user credentials in users.json

`users.json` stores **SHA-256 hashes only** — never plain-text passwords. The default file already contains hashes matching the original v1 passwords (see [Section 7](#7-credentials--roles)).

To set a new password for any user:

**1. Generate the SHA-256 hash** — open Command Prompt and run:

```cmd
python -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"
```

**2. Paste the output into `users.json`:**

```json
{
  "_comment": "SHA-256 hashes only — never store plain-text passwords here.",
  "_generate": "python -c \"import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())\"",
  "client1": {
    "password_sha256": "bd94dcda26fccb4e68d6a31f9b5aac0b571ae266d822620e901ef7ebe3a11d4f",
    "role": "guest"
  },
  "client2": {
    "password_sha256": "2b04b30e6d16e88a1d9803fe1c0948399fec97b552900bd0fa3fecee9ddd68da",
    "role": "operator"
  },
  "admin": {
    "password_sha256": "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
    "role": "admin"
  }
}
```

Valid roles are `guest`, `operator`, and `admin`. Any entry with the placeholder value `REPLACE_WITH_SHA256_HASH` is skipped with a warning on startup.

> **First-run behaviour:** If `users.json` is missing when the server starts, it auto-generates a template file and exits with instructions. Fill in the hashes and restart.

---

### Step 4 — Allow port 9999 through Windows Firewall

Open **PowerShell as Administrator** and run:

```powershell
New-NetFirewallRule -DisplayName "RCE Server" -Direction Inbound `
    -Protocol TCP -LocalPort 9999 -Action Allow
```

---

### Step 5 — Start the server

```cmd
cd C:\project
python server_v2.py
```

Expected startup output:

```
2025-01-01 12:00:00  [*] Loaded 3 user(s) from users.json
2025-01-01 12:00:00  [*] Secure RCE Server v2  listening on 0.0.0.0:9999  (asyncio + TLS)
2025-01-01 12:00:00  [*] Roles: ['guest', 'operator', 'admin']
2025-01-01 12:00:00  [*] Audit log -> logs/audit.log
```

**Keep this window open.** Press `Ctrl+C` to stop the server.

---

### Step 6 — Find the server's IP address

Clients on other machines need this to connect:

```cmd
ipconfig
```

Look for **IPv4 Address** under your active network adapter (e.g. `192.168.1.10`). Note it down.

---

## 5. Client Setup (Step-by-Step)

Repeat these steps on **each client machine**.

### Step 1 — Create the project folder

```cmd
mkdir C:\project
mkdir C:\project\certs
```

Copy `client_v2.py` into `C:\project\`.

---

### Step 2 — Copy the three certificate files from the server

Each client needs exactly **three files** from the server's `certs\` folder:

- `ca.crt` — the Certificate Authority certificate
- `client.crt` — the client's TLS certificate
- `client.key` — the client's private key

Place all three in `C:\project\certs\` on the client machine. You can transfer them using any of these methods:

**Option A — USB drive**

Copy the three files to a USB stick and paste them into `C:\project\certs\` on the client.

**Option B — Quick Python HTTP server (easiest)**

On the **server**, run:

```cmd
cd C:\project\certs
python -m http.server 8080
```

Then on the **client**, open a browser and go to `http://<SERVER-IP>:8080/`. Download `ca.crt`, `client.crt`, and `client.key` and save them to `C:\project\certs\`. Stop the HTTP server with `Ctrl+C` when done.

**Option C — Shared network folder**

Access the server's certs folder via `\\<SERVER-IP>\SharedFolder` and copy the three files.

> ⚠️ **Do NOT copy `server.crt`, `server.key`, or `ca.key` to clients.** Only the three files listed above are needed on the client side.

---

### Step 3 — Connect to the server

From a **remote machine** (replace with actual server IP):

```cmd
cd C:\project
python client_v2.py --host 192.168.1.10 --port 9999
```

From the **same machine as the server** (uses `127.0.0.1` by default):

```cmd
cd C:\project
python client_v2.py
```

---

### Step 4 — Log in

The client prompts for credentials:

```
[*] Connecting to 192.168.1.10:9999 (TLS) ...
[+] TLS connected  |  cipher: TLS_AES_256_GCM_SHA384

[server] Send credentials
Username: client1
Password:
[+] Welcome client1! Role: guest. Type a command.
    Role     : guest
    Commands : date, dir, echo, findstr, hostname, time, type, ver, whoami
```

---

## 6. Using the Shell

### 6.1 Running Commands

Type any command from your allowed list and press Enter:

- **stdout** — printed normally
- **stderr** — printed in red, prefixed with `[stderr]`
- **Non-zero exit code** — shown in yellow as `[exit N]`

---

### 6.2 Built-in Client Commands

| Command | What It Does |
|---------|-------------|
| `help` | Lists your allowed commands (no server round-trip) |
| `exit` / `quit` / `q` | Sends a clean disconnect message and exits |
| `Ctrl+C` | Also triggers a clean disconnect |

---

### 6.3 Command Examples by Role

**guest**

```
client1(guest)@remote> whoami
DESKTOP-ABC\user

client1(guest)@remote> ver
Microsoft Windows [Version 10.0.22621.3447]

client1(guest)@remote> date
Sun 05/04/2026

client1(guest)@remote> time
14:32

client1(guest)@remote> dir C:\Temp
 Volume in drive C has no label.
 Directory of C:\Temp
...

client1(guest)@remote> type C:\Temp\notes.txt
Hello from the server.

client1(guest)@remote> findstr /i "error" C:\Temp\log.txt
12: error: connection refused
```

**operator** (all guest commands, plus):

```
client2(operator)@remote> ipconfig /all
client2(operator)@remote> tasklist /v
client2(operator)@remote> netstat -ano
client2(operator)@remote> systeminfo
client2(operator)@remote> wmic cpu get name
client2(operator)@remote> dir C:\Windows\System32
client2(operator)@remote> type C:\Windows\System32\drivers\etc\hosts
```

**admin** (all operator commands, plus):

```
admin(admin)@remote> net user
admin(admin)@remote> net localgroup Administrators
admin(admin)@remote> ping -n 4 8.8.8.8
admin(admin)@remote> tracert -d google.com
admin(admin)@remote> wmic os list brief
admin(admin)@remote> net share
```

---

## 7. Credentials & Roles

These are the default built-in accounts. **Change all passwords before any real use** by editing `users.json`.

| Username | Password | SHA-256 Hash (stored in users.json) | Role |
|----------|----------|-------------------------------------|------|
| `client1` | `pass1234` | `bd94dcda26fccb4e68d6a31f9b5aac0b571ae266d822620e901ef7ebe3a11d4f` | `guest` |
| `client2` | `secure99` | `2b04b30e6d16e88a1d9803fe1c0948399fec97b552900bd0fa3fecee9ddd68da` | `operator` |
| `admin` | `admin123` | `240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9` | `admin` |

### Adding or Changing Users

Edit `users.json` — do not touch `server_v2.py`. Valid roles are `guest`, `operator`, and `admin`.

**1. Generate a hash for the new password:**

```cmd
python -c "import hashlib; print(hashlib.sha256(b'newpassword').hexdigest())"
```

**2. Add or update the entry in `users.json`:**

```json
"alice": {
  "password_sha256": "<paste hash here>",
  "role": "operator"
}
```

**3. Restart the server** — it reloads `users.json` on every start.

---

## 8. Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| `[x] Could not connect` | Server not running, wrong IP, or firewall blocking 9999 | Check the server terminal; verify IP with `ipconfig`; add the firewall rule (Section 4, Step 4) |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Client is missing `ca.crt`, `client.crt`, or `client.key` | Copy all three cert files from the server into `C:\project\certs\` on the client |
| TLS handshake fails immediately | Server rejected the client — no valid client certificate | Ensure `client.crt` and `client.key` are in `certs\` and were signed by your CA (re-run `gen_certs.sh` if needed) |
| `403` / command not allowed | Command not in your role's whitelist | Run `help` to see your allowed commands |
| `Path outside allowed prefix` | Tried to access a path outside your role's allowed directory | `guest`: use `C:\Temp` only. `operator`: paths under `C:\` |
| `IP banned. Try again in Xs` | 5 consecutive failed login attempts from your IP | Wait 30 seconds, then retry with correct credentials |
| `users.json not found` | File missing — server exited and created a template | Fill in the `password_sha256` values in the generated template, then restart |
| User skipped on startup | `password_sha256` still says `REPLACE_WITH_SHA256_HASH` | Generate a real SHA-256 hash and paste it in (see Section 7) |
| `date` / `time` hangs | Should be fixed in v2 — server auto-appends `/t` | If it still occurs, make sure you're running the updated `server_v2.py` |
| `'python' is not recognized` | Python not in PATH | Reinstall Python and tick **Add Python to PATH**, or use the full path: `C:\Python312\python.exe` |
| Server crashes with asyncio SSL error | Wrong event loop policy on Windows | Ensure the `WindowsSelectorEventLoopPolicy` line is at the top of `server_v2.py` (already included in v2) |
| Output shows garbled characters | Encoding mismatch | Run the server in **Windows Terminal** (supports UTF-8 by default) |

---

## 9. Security Notes

### What Is Protected

- **Passwords are hashed.** SHA-256 hashes are stored in `users.json`. Plain-text passwords are never written to disk or logs.
- **Mutual TLS.** The server requires a client certificate signed by your CA. Machines without a valid cert are rejected at the handshake — before any authentication prompt or Python logic.
- **Argument validation is server-side.** Clients cannot bypass flag or path restrictions by modifying their copy of `client_v2.py`.
- **Shell injection is mitigated.** Commands are split into a list before passing to `subprocess`. Only known shell built-ins use `shell=True`, and all commands are still checked against the whitelist first.
- **The audit log records everything.** Review `logs\audit.log` regularly. Each line is a JSON object parseable with PowerShell or `jq`.

### Known Limitations

- **Self-signed CA.** Acceptable for a lab. For production: get a CA-signed cert and set `check_hostname = True` in the client.
- **Single shared client certificate.** All clients use the same `client.crt` / `client.key`. For production, issue individual certificates per machine so you can revoke access per device.
- **Rate limiting is in-memory.** Restarting the server resets all failure counters and lockouts.
- **SHA-256 without salt.** Sufficient for a lab. For production, use `bcrypt` or `Argon2` via the `passlib` package.

---

## 10. Audit Log Reference

Every significant event is written as a JSON line to `logs\audit.log`:

```json
{"ts":"2025-01-01T12:00:00Z","user":"client2","ip":"192.168.1.5","action":"CMD","detail":"ipconfig /all","status":"code=0"}
```

| Field | Description |
|-------|-------------|
| `ts` | UTC timestamp in ISO 8601 format |
| `user` | Authenticated username (or `unknown` before login) |
| `ip` | Client IP address |
| `action` | `LOGIN`, `CMD`, `DISCONNECT`, or `PROTO_ERR` |
| `detail` | The full command string (for `CMD`), or `role=X` (for `LOGIN`) |
| `status` | `SUCCESS`, `FAIL`, `OK`, `ERROR`, or `code=N` (command exit code) |

---

## 11. Quick Reference Card

```
# GENERATE CERTS (server, once — run in Git Bash)
bash gen_certs.sh

# START SERVER
cd C:\project
python server_v2.py

# CONNECT (same machine as server)
python client_v2.py

# CONNECT (remote machine)
python client_v2.py --host <SERVER-IP> --port 9999

# CHANGE A PASSWORD
python -c "import hashlib; print(hashlib.sha256(b'newpassword').hexdigest())"
→ paste hash into users.json → restart server

# Default port:        9999 (TCP)
# CA cert:             certs\ca.crt       (server + all clients)
# Client cert/key:     certs\client.crt   (all clients)
#                      certs\client.key   (all clients)
# Audit log:           logs\audit.log     (server only)
# Stop server:         Ctrl+C
```