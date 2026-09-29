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
- **Evidence-First**: Every finding links to precise packet frames, TCP streams, protocol commands, TLS handshake fields, and X.509 certificates.
- **No Fabricated Facts**: Strict adherence to ground truth. When evidence is incomplete, findings explicitly record `UNKNOWN` / `INSUFFICIENT_EVIDENCE`.
- **100% Free & Air-Gapped Deployable**: Built entirely on open-source tools (TShark/PyShark, Scikit-Learn, FastAPI, React/Vite, PostgreSQL) without proprietary cloud dependencies.

---

## Platform Features & Stage Pipeline

- **PCAP Ingestion & Processing**: SHA-256 file hashing, safe validation, stream parsing, and metadata indexing.
- **Protocol Identification & Flow Reconstruction**: Signature-based SMTP/IMAP/POP3 detection and bidirectional TCP conversation stream assembly.
- **STARTTLS & TLS Forensics**: STARTTLS upgrade state machine, TLS 1.2/1.3 Hello handshake parsing, cipher suite analysis, and X.509 certificate chain validation.
- **Cryptographic Rules Engine**: YAML-configured security rules producing severity, confidence, evidence links, and remediation.
- **Unified Security Findings**: Correlated finding matrix with deduplication and evidence chain explorer.
- **Explainable Security Posture Aggregation**: Low/Medium/High/Critical posture scoring ($0-100$) with contributing deduction rationales.
- **Machine Learning Suite**: Synthetic dataset generator, Random Forest risk classifier, Isolation Forest unsupervised TLS anomaly detector, and synthetic mutation evaluator.
- **Risk Prioritization & Remediation Engine**: Risk Priority Score ($S_{priority} \in [0, 100]$), SHAP feature attributions, and deterministic Postfix/Dovecot/OpenSSL hardening action catalog.
- **Security Dashboard & Evidence Explorer**: Tabbed React dashboard overview, interactive evidence chain graph, and direct module launcher matrix.
- **Database Persistence & Restart Recovery**: State transition validation, PostgreSQL schema hardening, and automated service restart job recovery.
- **Dockerization & Deployment Packaging**: Reproducible Docker Compose stack, automated deployment scripts (`startup.sh`, `healthcheck.sh`, `verify_offline_deployment.sh`), and demo data fixtures.

---

## Automated Deployment Scripts

Located in `scripts/`:

- `scripts/startup.sh`: One-command automated deployment script. Verifies Docker runtime, initializes `.env`, launches container stack, and waits for health probes.
- `scripts/healthcheck.sh`: Probes backend liveness (`/health`), database readiness (`/ready`), system info (`/info`), and frontend server.
- `scripts/verify_offline_deployment.sh`: Audits source code for cloud API dependencies and verifies air-gapped offline compatibility.

---

## Quickstart Guide

### Option 1: Automated One-Command Startup (Recommended)

```bash
cd SecureMailScope
./scripts/startup.sh
```

### Option 2: Docker Compose

```bash
cd SecureMailScope
cp .env.example .env
docker compose up -d --build
```

Access services:
- **Frontend Security Dashboard**: [http://localhost:3000](http://localhost:3000) or [http://localhost:5173](http://localhost:5173)
- **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Probe**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)
- **Database Readiness Probe**: [http://localhost:8000/api/v1/health/ready](http://localhost:8000/api/v1/health/ready)

### Option 3: System Health Check

```bash
./scripts/healthcheck.sh
```

---

## Demo Data & Offline Testing

Sample fixtures are provided in `demo_data/`:

- `demo_data/sample_email_capture.pcap`: Sample PCAP capture containing email protocol streams.
- `demo_data/synthetic_anomaly_sample.json`: Pre-generated synthetic mutation dataset sample.

To upload demo capture via API:
```bash
curl -X POST "http://localhost:8000/api/v1/pcap/upload" \
  -F "file=@demo_data/sample_email_capture.pcap"
```

---

## Running Backend Test Suite

```bash
cd SecureMailScope/backend
source .venv/bin/activate
pytest tests -vv
```

---

## Directory Structure

```
SecureMailScope/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # REST API endpoints (health, pcap, jobs, ml, prioritization, recommendations, reports)
│   │   ├── models/          # SQLAlchemy database models (jobs, packets, sessions, findings, ML, reports)
│   │   ├── schemas/         # Pydantic v2 schemas
│   │   ├── services/        # Forensic analyzer engines & persistence service
│   │   ├── config.py        # Settings & environment configuration
│   │   ├── database.py      # SQLAlchemy engine & session management
│   │   └── main.py          # FastAPI application & lifecycle recovery
│   ├── tests/               # Pytest suite (150+ unit/integration tests)
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/      # React components (DashboardView, EvidenceExplorerModal, Modals)
│   │   ├── services/api.ts  # Typed API client
│   │   ├── App.tsx          # Main application view
│   │   └── main.tsx         # React entry point
│   ├── nginx.conf
│   └── Dockerfile
├── demo_data/               # Sample PCAP fixtures & synthetic datasets
├── scripts/                 # Deployment automation scripts (startup.sh, healthcheck.sh, verify_offline_deployment.sh)
├── docker-compose.yml       # Production container stack (db, backend, frontend)
├── .env.example             # Environment variable template
└── README.md
```
