# SecureMailScope Demo Data & Offline Fixtures

This directory contains offline demonstration data, sample email PCAP captures, and synthetic mutation datasets for testing and offline deployment without requiring internet access.

## Contents

- `sample_email_capture.pcap`: Sample packet capture containing observable SMTP, IMAP, POP3, and TLS 1.2/1.3 email traffic with STARTTLS upgrade sequences.
- `synthetic_anomaly_sample.json`: Pre-generated synthetic mutation dataset containing ground-truth labeled email security scenarios (secure baseline, weak ciphers, expired certificates, unencrypted authentication bursts) for offline ML training.

## Usage

1. **PCAP Upload Demo**: Upload `sample_email_capture.pcap` via the frontend dashboard or using the REST API:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/pcap/upload" \
     -F "file=@demo_data/sample_email_capture.pcap"
   ```

2. **Offline ML Dataset Generator**: Generate reproducible synthetic datasets using the ML Dataset Generator tab in the frontend or directly via REST API:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/ml/dataset/generate" \
     -H "Content-Type: application/json" \
     -d '{"sample_count": 100, "seed": 42}'
   ```
