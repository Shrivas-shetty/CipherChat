# CipherChat (Phase 1)

Two-user chat over a LAN. Messages stay in memory on the server; there is no auth, database, or encryption yet.

## Layout

```
backend/          FastAPI + WebSocket server
frontend/         Vite + React + TypeScript UI
```

## Backend setup

Requires Python 3.11+.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

On macOS/Linux:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Health check: `http://127.0.0.1:8000/api/health`

If `frontend/dist` exists, the backend also serves the built UI at `/`.

## Frontend setup

```powershell
cd frontend
npm install
npm run dev
```

- Dev server is reachable on the LAN (`vite` `server.host = true`).
- Point the server-address boxes at the host laptop (`IP` + port `8000`).

Production build (served by the backend):

```powershell
cd frontend
npm install
npm run build
```

Then open `http://<host-LAN-IP>:8000` on another machine (backend must be running).

## Find the host laptop's LAN IP

**Windows**

```powershell
ipconfig
```

Use the IPv4 address of the active Wi‑Fi/Ethernet adapter (usually `192.168.x.x`).

**Linux / macOS**

```bash
ip a
# or
ifconfig
```

## Windows Firewall (host laptop)

Allow inbound TCP **8000** on the **Private** profile so other devices on the LAN can reach the server:

1. Windows Security → Firewall & network protection → Advanced settings  
2. Inbound Rules → New Rule → Port → TCP → Specific local ports: `8000`  
3. Allow the connection → check **Private** → name it e.g. `CipherChat 8000`

Or PowerShell (Admin):

```powershell
New-NetFirewallRule -DisplayName "CipherChat 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private
```

## Two-laptop test procedure

1. On laptop A (host): start the backend on `0.0.0.0:8000`.  
2. Optionally `npm run build` in `frontend/` so A serves the UI.  
3. On laptop B: open `http://<A-LAN-IP>:8000`, set a display name, Join.  
4. On laptop A: open the same URL (or use `npm run dev` and point the address boxes at A's LAN IP / `127.0.0.1`).  
5. Confirm pairing, message order, and that a third joiner gets `ROOM_FULL`.

## WebSocket protocol (v1)

Every frame: `{"v":1,"type":"......", ...}`

| Direction | type | Fields |
|-----------|------|--------|
| C→S | `join` | `display_name` (1–20, unique, case-insensitive) |
| C→S | `chat` | `text` (1–2000 after trim) |
| S→C | `joined` | `display_name`, `user_id` |
| S→C | `status` | `state`: `waiting` \| `paired`, `peer` |
| S→C | `chat` | `id`, `sender`, `text`, `ts` (to both users) |
| S→C | `peer_left` | `display_name` |
| S→C | `error` | `code`, `message` |

Error codes: `ROOM_FULL`, `NAME_TAKEN`, `BAD_FRAME`, `NOT_JOINED`.

## Acceptance tests

1. Backend starts on `0.0.0.0:8000`; `/api/health` works from the same machine.  
2. Two browser tabs on one machine (different display names) pair up and exchange messages in order.  
3. A third tab gets `ROOM_FULL`. A duplicate name gets `NAME_TAKEN`.  
4. Closing one tab shows "Peer left" and "Waiting for User B…" in the other.  
5. From a second laptop, `http://<host-LAN-IP>:8000` (after `npm run build`) works, **and** the Vite dev server with the server-address boxes pointed at the host also works.  
6. Sending malformed JSON does not crash the server.
