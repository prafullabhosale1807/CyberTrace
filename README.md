# CyberTrace — File Integrity and Digital Evidence Monitoring System

CyberTrace is an academic project that demonstrates file-integrity monitoring and basic digital-evidence logging. It uses SHA-256 hashes to compare a registered baseline file with a later upload and records integrity events.

## Technology stack
- Frontend: HTML, CSS, JavaScript
- Backend: Python and Flask
- Database: SQLite
- Hashing: SHA-256
- Password hashing: Werkzeug

## Features
- Administrator and investigator login roles
- Register a file as a monitored baseline
- Verify file integrity by comparing SHA-256 hashes
- Store file status and audit/evidence events in SQLite
- Dashboard and REST API integration

## Project structure
```text
CyberTrace/
├── frontend/              # HTML, CSS and JavaScript UI
└── backend/
    ├── app.py             # Flask API
    ├── database.py        # SQLite schema and demo account setup
    ├── hashing.py         # SHA-256 helpers
    ├── requirements.txt
    ├── database/          # Local runtime database (not committed)
    └── evidence_files/    # Local monitored files (not committed)
```

## Run locally (Windows)
1. Install Python 3.10 or newer.
2. Open a terminal in `backend/`.
3. Create and activate a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python app.py
   ```
4. Open `frontend/index.html` with VS Code Live Server. The frontend expects the backend at `http://127.0.0.1:5000`.
5. The SQLite database is created and initialized when the backend starts.

## Demo accounts
The current code initializes academic-demo accounts on first run:
- Admin: `admin` / `admin123`
- Investigator: `investigator` / `investigator123`

These are demonstration credentials only. Do not use them in a production deployment.

## API examples
- `GET /` — backend status
- `GET /api/health` — health check
- `POST /api/login` — authenticate a user
- `POST /api/files/upload` — register a baseline file
- `GET /api/files` — list monitored files
- `GET /api/evidence` — list evidence events
- `GET /api/logs` — audit logs
- `GET /api/dashboard` — dashboard data

## Security notes
This is an educational project, not a production-ready evidence-management platform. Do not upload real confidential evidence or real user records. Keep runtime databases, uploaded evidence, credentials, and secrets out of the public repository. Add production-grade authorization, audit protections, upload validation, and deployment security before real-world use.
