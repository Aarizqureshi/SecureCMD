# Secure Remote Command Execution System — v2
**Jackfruit Mini Project · Deliverable 2 · Windows Edition**

A role-based remote command shell secured with TLS, built entirely on Python's standard library. A single server accepts multiple simultaneous clients. Each client authenticates, receives a role, and can only run the commands that role permits — all traffic encrypted end-to-end.

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

---

## 1. How It Works

### 1.1 Overall Architecture

```
  CLIENT A ──┐
             ├──(TLS/TCP)──► SERVER (asyncio, single thread)
  CLIENT B ──┘                  │
                                ├─ authenticates each client
                                ├─ checks role & command whitelist
                                ├─ runs command via subprocess
                                └─ streams result back
```

The server runs a single asyncio event loop. Each connected client gets its own `handle_client` coroutine. While one client waits on I/O, the loop services others — no threads needed.

---

### 1.2 TLS Connection

The server wraps its TCP socket with TLS using a self-signed certificate (`server.crt` / `server.key`). The client loads `server.crt` as its trust anchor and verifies the server's identity before any data is exchanged. **No plaintext crosses the network at any point.**

> **Why self-signed?** Acceptable for a controlled lab. In production, use a CA-signed certificate and set `check_hostname = True` in the client.

---

### 1.3 Message Framing (Length-Prefix Protocol)

Every message — auth packets, commands, results — is sent as UTF-8 JSON with a **4-byte big-endian length header** prepended.

```
┌──────────────────────┬────────────────────────────────┐
│  4 bytes (length)    │  N bytes (JSON payload)        │
└──────────────────────┴────────────────────────────────┘
```

The receiver reads exactly 4 bytes, converts to an integer, then reads exactly that many bytes of JSON. This eliminates any ambiguity about message boundaries. Messages over 64 KB are rejected on both sides to prevent memory exhaustion.

---

### 1.4 Authentication Flow

```
SERVER                              CLIENT
  │                                    │
  │── { type: "auth_request" } ───────►│
  │                                    │  (user types username + password)
  │◄── { type: "auth", username, pw } ─│
  │                                    │
  │  [SHA-256 hash pw, compare to DB]  │
  │                                    │
  │── { type: "auth_ok",  ────────────►│   ← includes role + allowed commands
  │     role, allowed_commands }        │
  │                        OR           │
  │── { type: "auth_fail" } ──────────►│   ← failure counter incremented for IP
```

Passwords are **never stored in plain text** — only their SHA-256 hashes are in the user database.

---

### 1.5 Rate Limiting & IP Lockout

The server tracks authentication failures per IP address in memory.

| Setting | Value |
|---|---|
| Failures before lockout | 5 |
| Lockout duration | 30 seconds |
| Scope | Per connecting IP address |
| Reset on | Successful login |

A banned IP receives an immediate `auth_fail` and the connection is dropped before the handshake even starts.

---

### 1.6 Role-Based Access Control (RBAC)

Three roles exist, each with a fixed whitelist of Windows commands. For every incoming command the server checks three things in order:

1. **Is the base command in this role's whitelist?** If not → `403 error`, not executed.
2. **Are all flags in the `allowed_flags` set for this command?** If not → `403 error`.
3. **If the command takes a path, does the resolved path start with `allowed_path_prefix`?** `Path.resolve()` is used to defeat symlink and `..` traversal tricks.

| Role | Allowed Commands | Path Restriction |
|---|---|---|
| `guest` | `whoami`, `hostname`, `echo`, `date`, `time`, `ver`, `dir`, `type`, `findstr` | `dir` / `type` / `findstr` → `C:\Temp` only |
| `operator` | All guest commands + `ipconfig`, `tasklist`, `systeminfo`, `netstat`, `wmic` | `dir` / `type` → anywhere under `C:\` |
| `admin` | All operator commands + `net`, `ping`, `tracert` | No path restriction |

---

### 1.7 Windows Command Execution

Many Windows commands (`dir`, `echo`, `type`, `ver`, etc.) are **shell built-ins inside `cmd.exe`** — they cannot be launched as standalone executables. The server handles this:

```python
SHELL_BUILTINS = {"date", "time", "dir", "ver", "echo", "type", ...}

# shell built-ins → run via cmd.exe
subprocess.run(cmd, shell=True, ...)

# standalone executables (ping, whoami, etc.) → direct launch, safer
subprocess.run(parts, shell=False, ...)
```

Both paths are still gated through the role whitelist before execution. Output is captured as UTF-8, decoded with `errors="replace"` to handle any encoding edge cases, and sent back inside a `result` message.

---

### 1.8 Audit Logging

Every significant event is written as a JSON line to `logs/audit.log`:

```json
{"ts":"2025-01-01T12:00:00Z","user":"client2","ip":"192.168.1.5","action":"CMD","detail":"ipconfig /all","status":"code=0"}
```

Fields: `ts` (UTC timestamp), `user`, `ip`, `action`, `detail`, `status`. The log is also mirrored to the server's console window.

---

## 2. Prerequisites

Install the following on **all machines** (server and both clients) before doing anything else.

| Requirement | Notes |
|---|---|
| **Python 3.11+** | Download from [python.org](https://python.org/downloads). During install, tick **"Add Python to PATH"**. |
| **OpenSSL** | Needed only on the **server** to generate the certificate. The easiest way to get it on Windows is via **Git for Windows** ([git-scm.com](https://git-scm.com)). |
| **C:\Temp folder** | Must exist on the **server** for guest-role path restrictions to work. |
| **No third-party packages** | Everything uses the Python standard library only (`asyncio`, `ssl`, `json`, `subprocess`, `hashlib`, `logging`). |

> **Verify Python is installed correctly** — open a new Command Prompt and run:
> ```
> python --version
> ```
> You should see `Python 3.11.x` or higher.

---

## 3. Folder Structure

```
project\
    server_v2.py
    client_v2.py
    certs\
        server.crt      ← certificate  (copy this file to clients)
        server.key      ← private key  (server only — never share this)
    logs\               ← created automatically on first server start
        audit.log
```

On **client machines**, you only need:
```
project\
    client_v2.py
    certs\
        server.crt      ← copied from the server
```

---

## 4. Server Setup (Step-by-Step)

### Step 1 — Create the project folders

Open **Command Prompt** and run:

```cmd
mkdir C:\project
mkdir C:\project\certs
mkdir C:\Temp
```

Copy `server_v2.py` into `C:\project\`.

---

### Step 2 — Generate the TLS certificate

Open **Git Bash** (right-click the Start menu → Git Bash) and run this single command:

```bash
cd /c/project/certs
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

You should now have two files in `C:\project\certs\`:
- `server.crt` — the certificate (share this with clients)
- `server.key` — the private key (**never share this**)

---

### Step 3 — Allow port 9999 through Windows Firewall

Open **PowerShell as Administrator** and run:

```powershell
New-NetFirewallRule -DisplayName "RCE Server" -Direction Inbound -Protocol TCP -LocalPort 9999 -Action Allow
```

---

### Step 4 — Start the server

```cmd
cd C:\project
python server_v2.py
```

Expected output:
```
2025-01-01 12:00:00  [*] Secure RCE Server v2  listening on 0.0.0.0:9999  (asyncio + TLS)
2025-01-01 12:00:00  [*] Roles: ['guest', 'operator', 'admin']
2025-01-01 12:00:00  [*] Audit log -> logs/audit.log
```

The server is now running. **Keep this window open.** Press `Ctrl+C` to stop it.

---

### Step 5 — Find the server's IP address

You will need this for the clients to connect.

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

### Step 2 — Copy the server certificate to the client

Copy `server.crt` from the server's `C:\project\certs\` to the **same path** on the client: `C:\project\certs\server.crt`.

You can transfer the file using any of these methods:
- USB drive
- Shared folder: `\\<SERVER-IP>\SharedFolder`
- Quick Python HTTP server on the server (run `python -m http.server 8080` in `C:\project\certs\`, then open `http://<SERVER-IP>:8080/server.crt` in the client's browser and save the file)

> **Do NOT copy `server.key` to clients.** That is the server's private key.

---

### Step 3 — Connect to the server

```cmd
cd C:\project
python client_v2.py --host 192.168.1.10 --port 9999
```

Replace `192.168.1.10` with the actual server IP from Step 5 of the server setup.

If running the client **on the same machine as the server**, omit `--host` entirely (it defaults to `127.0.0.1`):

```cmd
python client_v2.py
```

---

### Step 4 — Log in

The client will prompt for credentials:

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

### Running commands

Type any command from your allowed list and press Enter:

```
client1(guest)@remote> whoami
DESKTOP-ABC\user

client1(guest)@remote> ver
Microsoft Windows [Version 10.0.22621.3447]

client1(guest)@remote> dir C:\Temp
 Volume in drive C has no label.
 Directory of C:\Temp
...
```

- **stdout** — printed normally
- **stderr** — printed in red, prefixed with `[stderr]`
- **Non-zero exit code** — shown in yellow as `[exit N]`

---

### Special client commands

| Command | What it does |
|---|---|
| `help` | Lists your allowed commands (no server round-trip) |
| `exit` / `quit` / `q` | Sends a clean disconnect message and exits |
| `Ctrl+C` | Also triggers a clean disconnect |

---

### Command examples by role

**guest**
```
whoami
hostname
ver
date /t
time /t
dir C:\Temp
type C:\Temp\notes.txt
findstr /i "error" C:\Temp\log.txt
```

**operator** (all guest commands, plus)
```
ipconfig /all
tasklist /v
netstat -ano
systeminfo
wmic cpu get name
dir C:\Windows\System32
type C:\Windows\System32\drivers\etc\hosts
```

**admin** (all operator commands, plus)
```
net user
net localgroup Administrators
ping -n 4 8.8.8.8
tracert -d google.com
wmic os list brief
net share
```

---

## 7. Credentials & Roles

These are the default built-in accounts. **Change them before any real use** by editing the `USERS` dictionary in `server_v2.py`.

| Username | Password | Role |
|---|---|---|
| `client1` | `pass1234` | `guest` |
| `client2` | `secure99` | `operator` |
| `admin` | `admin123` | `admin` |

To add or change a user, edit `server_v2.py`:

```python
def _h(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

USERS = {
    "alice": (_h("mynewpassword"), "operator"),
    "admin": (_h("changemeplease"), "admin"),
}
```

---

## 8. Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| `[x] Could not connect` | Server not running, wrong IP, or firewall blocking 9999 | Check the server terminal; verify IP with `ipconfig`; add the firewall rule (Section 4 Step 3) |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Client does not have the server certificate | Copy `server.crt` to the client's `certs\` folder |
| `403` / command not allowed | Command not in your role's whitelist | Run `help` to see your allowed commands |
| `Path outside allowed prefix` | Tried to access a path outside your role's allowed directory | `guest`: use `C:\Temp` only; `operator`: use paths under `C:\` |
| `IP banned. Try again in Xs` | 5 consecutive failed login attempts from your IP | Wait 30 seconds, then retry with correct credentials |
| `'python' is not recognized` | Python not in PATH | Reinstall Python and tick "Add Python to PATH", or use the full path: `C:\Python312\python.exe` |
| Server crashes with asyncio SSL error | Wrong event loop policy | Ensure the `WindowsSelectorEventLoopPolicy` line is at the top of `server_v2.py` (already included in v2) |
| Output shows garbled characters | Encoding mismatch | The server uses `encoding="utf-8", errors="replace"` — if garbling persists, run the server in a terminal that supports UTF-8 (Windows Terminal is recommended) |

---

## 9. Security Notes

- **Passwords are hashed.** SHA-256 hashes are stored in `USERS`. Plain-text passwords are never written to disk or logs.
- **The certificate is self-signed.** Fine for a lab. For production: get a CA-signed cert and set `check_hostname = True` in the client.
- **Argument validation is server-side.** Clients cannot bypass flag or path restrictions by modifying their copy of the script.
- **Shell injection is mitigated.** Commands are split into a list and passed to `subprocess`. Only known shell built-ins use `shell=True`, and those commands are still checked against the whitelist before execution.
- **The audit log records everything.** Review `logs\audit.log` regularly. Each line is a JSON object parseable with PowerShell or `jq`.
- **Rate limiting is in-memory only.** Restarting the server resets all failure counters and lockouts.

---

## Quick Reference

```
# Start the server
cd C:\project
python server_v2.py

# Connect from the same machine
python client_v2.py

# Connect from a remote machine
python client_v2.py --host <SERVER-IP> --port 9999

# Default port:    9999 (TCP)
# Certificate:     certs\server.crt  (both machines)
# Audit log:       logs\audit.log    (server only)
# Stop server:     Ctrl+C
```
