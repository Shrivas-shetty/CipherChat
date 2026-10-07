# CipherChat (Phase 2)

Secure two-user chat over a LAN with user accounts, JWT sessions with server-side revocation, and a tamper-evident audit log with SHA-256 hash chaining.

> [!WARNING]
> **Known Limitation (Educational LAN Analysis):**
> Traffic is plain HTTP/WS, so credentials and JWT tokens are visible in plaintext to anyone sniffing the LAN. This is intentional for the project's Wireshark traffic analysis and inspection laboratory exercises. End-to-end encryption and key exchange will be implemented in subsequent phases.

---

## Architecture Overview

```
CipherChat/
├── backend/                  FastAPI + WebSocket server (SQLAlchemy 2.0 + SQLite)
│   ├── app/
│   │   ├── config.py         Config, DB_PATH, JWT settings, lockout policy
│   │   ├── deps.py           Auth dependencies (get_current_user, require_role)
│   │   ├── main.py           FastAPI application factory, lifespan DB init, SPA serving
│   │   ├── db/
│   │   │   ├── base.py       SQLAlchemy engine, WAL PRAGMA, SessionLocal, init_db
│   │   │   └── models.py     User, AuthSession, AuditLog models
│   │   ├── routers/
│   │   │   ├── auth.py       /api/auth (register, login, logout, me)
│   │   │   ├── health.py     /api/health
│   │   │   └── ws.py         /ws (authenticated WebSocket endpoint)
│   │   ├── scripts/          CLI utilities (seed_analyst, show_audit, verify_audit)
│   │   ├── security/         Password hashing (bcrypt) and JWT tokens (HS256)
│   │   ├── services/         Audit logging with SHA-256 tamper-evident hash chaining
│   │   ├── tests/            Pytest auth & audit test suite
│   │   └── ws/
│   │       └── manager.py    Active ConnectionManager
│   └── data/                 SQLite database (app.db) and generated jwt_secret
└── frontend/                 Vite + React 19 + TypeScript SPA
    └── src/
        ├── api/              HTTP client (http.ts) with Bearer token & 401 handler
        ├── auth/             AuthContext & sessionStorage manager
        ├── components/       ServerAddressInput
        ├── pages/            AuthPage, ChatPage, AnalystPage
        └── ws/               ChatSocket (authenticated v1 WebSocket protocol)
```

---

## Dependencies

### Backend
- Python 3.11+
- `fastapi`
- `uvicorn[standard]`
- `sqlalchemy>=2.0`
- `bcrypt`
- `pyjwt`
- `pydantic-settings`
- Dev/Testing: `pytest`, `httpx`

### Frontend
- Node.js 18+
- React 19, TypeScript, Vite

---

## Setup & Running

### Backend setup

From `backend/`:

**Windows (PowerShell):**
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**macOS / Linux:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Health check: `http://127.0.0.1:8000/api/health`

### Frontend setup

From `frontend/`:

```powershell
cd frontend
npm install
npm run dev
```

The Vite development server is accessible on your LAN.

To generate a production build served directly by FastAPI:
```powershell
cd frontend
npm run build
```
Once built, open `http://<host-LAN-IP>:8000` in your browser.

---

## CLI Utilities

Run all commands from the `backend/` directory with your virtual environment activated:

### 1. Seed an Analyst User
Create a user with the `analyst` role (analysts cannot join chat rooms and are redirected to the Analyst Portal):
```powershell
python -m app.scripts.seed_analyst --username analyst1 --password AnalystPass123
```
If `--password` is omitted, you will be prompted securely using masked password input.

### 2. View Audit Logs
View audit events in a formatted table:
```powershell
python -m app.scripts.show_audit --tail 50
```
Filter by event type (e.g. `LOGIN_FAILED`, `REGISTER`, `ROOM_FULL`):
```powershell
python -m app.scripts.show_audit --type LOGIN_FAILED
```

### 3. Verify Audit Log Hash Chain Integrity
Verify that no audit logs have been tampered with or modified:
```powershell
python -m app.scripts.verify_audit
```
Outputs `OK` (exit code 0) if intact, or `Corrupted at row id: <id>` (exit code 1) if tampering is detected.

---

## Resetting the Database

To reset all users, sessions, and audit logs to a clean state:
1. Stop the backend server.
2. Delete the SQLite database file:
   ```powershell
   Remove-Item backend/data/app.db
   ```
   (On Linux/macOS: `rm backend/data/app.db`)
3. Restart the backend server. Tables will automatically be recreated on startup.

---

## Running Automated Tests

Run backend test suite using `pytest`:
```powershell
pytest -v backend/app/tests/test_auth.py
```

---

## Acceptance Tests

1. **User Registration:** Register user `alice` and `bob`. Weak passwords (< 8 bytes, no letters, or no digits) and duplicate usernames are rejected with clear messages.
2. **Authentication & Lockout:** Entering a wrong password shows the generic `"Invalid username or password"` error. After 5 consecutive failed attempts within 5 minutes, further attempts return HTTP 429 (`"Too many failed attempts"`). `show_audit` lists `LOGIN_FAILED` (alert) rows and `LOGIN_LOCKED`.
3. **Paired Chat:** Alice (tab 1) and Bob (tab 2, or another laptop) log in, automatically pair, and chat. Displayed names match their registered usernames.
4. **Room Full Enforcement:** A third registered user logging in and attempting to open chat receives `"Chat room is full, only 2 users allowed"`. A `ROOM_FULL` event is recorded in the audit log.
5. **Session Revocation (Logout):** When Alice clicks Logout, Bob immediately sees `"Peer left"` and `"Waiting for User B…"`. Alice's token is revoked in `auth_sessions`; calling `/api/auth/me` with the revoked token returns HTTP 401.
6. **Session Persistence & Superseding:** Refreshing Alice's tab keeps her logged in via `sessionStorage` and reconnects to the chat. Opening Alice's account in a second tab supersedes the first tab's WebSocket connection with `"You were signed in from another tab or device"`.
7. **Analyst Portal:** Seeding an analyst user via `seed_analyst` and logging in renders the placeholder `AnalystPage` (`"Security dashboard, coming in Phase 6"`). Analysts cannot join the live chat room.
8. **Tamper Detection:** Running `verify_audit` reports `OK`. Manually modifying any field of a row in `app.db` causes `verify_audit` to report the corrupted row ID.
9. **Automated Test Suite:** `pytest` passes cleanly.
