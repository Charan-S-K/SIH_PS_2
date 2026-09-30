# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

---

## Overview

SecureMailScope is an evidence-first passive network forensics platform designed to evaluate the cryptographic security posture of email communications across **SMTP**, **IMAP**, and **POP3**.

For complete application details, setup instructions, architecture documentation, and deployment guides, please see the [SecureMailScope Readme](SecureMailScope/README.md).

---

## Quickstart

```bash
cd SecureMailScope
cp .env.example .env
docker compose up -d --build
```

Access services:
- **Frontend Security Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Backend API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
