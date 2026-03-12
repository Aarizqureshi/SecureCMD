# Secure Remote Command Execution System
### Jackfruit Mini Project – Deliverable 1

---

## What This Project Does

A **client-server system** where authenticated clients connect over a **TLS-encrypted TCP socket** and remotely execute shell commands on the server. The server responds with the output.

```
[Client 1] ──TLS──┐
                   ├──► [Server] executes command ──► sends back output
[Client 2] ──TLS──┘
```

---

## Project Structure

```
secure_rce/
├── server.py          # Multi-threaded TLS server
├── client.py          # Interactive TLS client
├── certs/
│   ├── server.crt     # Self-signed SSL certificate
│   └── server.key     # Private key
└── logs/
    └── audit.log      # Audit trail (auto-created)
```

---

## Setup & Run

### Step 1 – Generate SSL Certificate (one-time)
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
  -out certs/server.crt -days 365 -nodes \
  -subj "/CN=localhost/O=SecureRCE/C=IN"
```

### Step 2 – Start the Server
```bash
python server.py
```

### Step 3 – Connect Client 1 (new terminal)
```bash
python client.py
# Username: client1
# Password: pass1234
```

### Step 4 – Connect Client 2 (another terminal)
```bash
python client.py
# Username: client2
# Password: secure99
```

---

## User Credentials

| Username | Password  |
|----------|-----------|
| client1  | pass1234  |
| client2  | secure99  |
| admin    | admin123  |

---

## Allowed Commands (Whitelist)

```
ls, pwd, whoami, date, echo, uname, uptime,
hostname, df, ps, cat, head, tail, wc, grep, env, id
```

Any other command is **rejected by the server** (code 403).

---

## Example Session

```
[*] Connecting to 127.0.0.1:9999 (TLS) ...
[✓] TLS connected  |  cipher: TLS_AES_256_GCM_SHA384

[server] Send credentials
Username: client1
Password: ****
[✓] Welcome client1! Type a command.

client1@remote> whoami
root

client1@remote> ls -la
total 20
drwxr-xr-x  ...

client1@remote> uname -a
Linux hostname 5.15.0 ...

client1@remote> exit
[*] Disconnected.
```

---
