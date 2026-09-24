# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**
*Smart India Hackathon 2024 / Problem Statement SIH26159*

---

## Overview

SecureMailScope is an evidence-first passive network forensics platform designed to evaluate the cryptographic security posture of email communications across **SMTP**, **IMAP**, and **POP3**.

### Core Architecture Philosophy

```
Observed Facts → Forensic Rules → Verifiable Evidence → ML Risk Scoring → Prioritization → Actionable Remediation
```

- **Passive & Non-Intrusive**: Analyzes captured network traffic (PCAP/PCAPNG) without interacting with live email servers.
- **Evidence-First**: Every finding links to precise packet frames, TCP streams, protocol commands, and TLS handshake fields.
- **No Fabricated Facts**: Strict adherence to ground truth. When evidence is incomplete, findings explicitly record `UNKNOWN` / `INSUFFICIENT_EVIDENCE`.
- **100% Free & Locally Deployable**: Built entirely on open-source tools without proprietary cloud dependencies.

---

## Stage 00 — Foundation Structure

This stage delivers the foundation for all 28 development stages:

- **Backend**: FastAPI with async health & readiness probes, Pydantic v2 configuration, CORS middleware, and SQLAlchemy PostgreSQL session management.
- **Frontend**: React + Vite + Tailwind CSS dashboard displaying live backend liveness, response latency, and database readiness.
- **Docker Compose**: Orchestration skeleton connecting PostgreSQL 16 Alpine, FastAPI Backend, and Nginx-served Frontend with container healthchecks.
- **Automated Tests**: Pytest suite covering configuration parsing, health liveness, readiness degradations, database timeouts, and CORS preflight.

---

## Directory Structure

```
SecureMailScope/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   └── health.py        # Liveness (/health), readiness (/ready), and info (/info)
│   │   ├── models/
│   │   │   └── base.py          # SQLAlchemy base & TimestampMixin
│   │   ├── config.py            # Pydantic Settings & environment variables
│   │   ├── database.py          # SQLAlchemy engine, session maker, and health probe
│   │   └── main.py              # FastAPI app lifecycle, CORS, routing
│   ├── tests/
│   │   ├── conftest.py          # TestClient fixtures and in-memory test DB
│   │   ├── test_config.py       # Configuration and CORS parsing tests
│   │   ├── test_database.py     # Base model and connection timeout tests
│   │   └── test_health.py       # Health probes & error handling tests
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/          # Navbar, HealthCard
│   │   ├── services/api.ts      # Typed API client for backend health probes
│   │   ├── App.tsx              # Main dashboard view
│   │   ├── index.css            # Tailwind styling
│   │   └── main.tsx             # React entry point
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── nginx.conf
│   └── Dockerfile
├── docker-compose.yml           # Multi-service stack (db, backend, frontend)
├── .env.example                 # Configuration template
└── README.md
```

---

## Quickstart

### Option 1: Docker Compose (Recommended)

```bash
cd SecureMailScope
cp .env.example .env
docker compose up -d --build
```

Access the services:
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000) or [http://localhost:5173](http://localhost:5173)
- **Backend API**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Liveness Probe**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)
- **Readiness Probe**: [http://localhost:8000/api/v1/health/ready](http://localhost:8000/api/v1/health/ready)

### Option 2: Local Bare-Metal Development

#### 1. Backend Setup
```bash
cd SecureMailScope/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Run backend
uvicorn app.main:app --reload --port 8000
```

#### 2. Frontend Setup
```bash
cd SecureMailScope/frontend
npm install
npm run dev
```

#### 3. Running Backend Tests
```bash
cd SecureMailScope/backend
source .venv/bin/activate
pytest -v --cov=app
```
