# Secure Webhook Receiver

A small Flask app that receives webhooks securely. It verifies that each request really comes from a trusted sender, rejects old or tampered requests, and ignores duplicate events. This pattern is used in event-driven MLOps/AIOps pipelines (CI/CD triggers, monitoring alerts, model registry events).

## What is a webhook?

A webhook is an endpoint that waits for events. When something happens in another system (a push, an alert, a new model version), that system sends an HTTP POST to your URL, and your code reacts. Because the URL is public, the receiver must verify who is calling.

## Features

- *HMAC-SHA256 signature verification* so only senders with the shared secret are accepted
- *Constant-time comparison* (hmac.compare_digest) to avoid timing attacks
- *Replay protection* using a timestamp (requests older than 5 minutes are rejected)
- *Idempotency* by event ID, so duplicate deliveries are processed once
- *Secret from an environment variable*, never hardcoded
- */health endpoint* (open, read-only) for uptime checks

## Project structure


webhook-receiver/
├── webhook_server.py   # Flask receiver (/webhook, /health)
├── test_webhook.py     # Test sender that signs requests and checks behavior
├── .env.example        # Example of the required environment variable
├── .gitignore
└── README.md


## Setup

bash
python3 -m venv venv
source venv/bin/activate
pip install flask requests


Generate a secret (32 random bytes = 64 hex characters) and export it:

bash
export WEBHOOK_SECRET=$(openssl rand -hex 32)


The server and the sender must use the *same* secret. Environment variables belong to one terminal, so in a second terminal export the same value.

## Run

Terminal 1 (leave it running):

bash
python3 webhook_server.py


Terminal 2:

bash
export WEBHOOK_SECRET=<same value>
python3 test_webhook.py


## How the signature works

1. The sender builds the JSON body and a Unix timestamp.
2. It computes HMAC-SHA256(secret, timestamp + "." + raw_body).
3. It sends the request with two headers:
   - X-Timestamp: <timestamp>
   - X-Signature: sha256=<hex digest>
4. The receiver recomputes the HMAC from the raw body and compares it with the header. The secret itself is never sent.

## Expected test results

| Test | Expected |
|---|---|
| Health check | 200 |
| Valid signature | 200 (processed) |
| Duplicate event | 200 (ignored) |
| Wrong secret | 401 |
| Tampered body | 401 |
| Old timestamp | 401 |
| Missing headers | 400 |

## Manual request with curl

bash
BODY='{"id":"abc123","type":"test"}'
TS=$(date +%s)
SIG="sha256=$(printf '%s' "$TS.$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')"

curl -X POST http://127.0.0.1:5000/webhook \
  -H "Content-Type: application/json" \
  -H "X-Timestamp: $TS" \
  -H "X-Signature: $SIG" \
  -d "$BODY"


## Security notes

- Never commit your secret. Keep it in an environment variable or .env (listed in .gitignore).
- Use HTTPS in production.
- If the secret leaks, generate a new one and update both sides.
- In production, store processed event IDs in a database or cache (Redis), and keep the secret in a secret manager (AWS Secrets Manager, Vault).
- The /health endpoint is intentionally open and must never return secrets or internal details.

## Tech

Python, Flask, HMAC-SHA256, OpenSSL

## Author

*Farhad Ali Zahid*, AI Operations (AIOps) student

[LinkedIn](https://www.linkedin.com/in/farhad-ali-zahid-99a846446)
