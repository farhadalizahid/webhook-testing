import hashlib
import hmac
import json
import os
import time
import uuid

import requests

URL = "http://127.0.0.1:5000"
SECRET = os.environ.get("WEBHOOK_SECRET")
if not SECRET:
    raise SystemExit("Set WEBHOOK_SECRET first: export WEBHOOK_SECRET=...")


def sign(secret, timestamp, body):
    payload = str(timestamp).encode() + b"." + body
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def send(body, secret=SECRET, timestamp=None, signed_body=None):
    """Send a webhook. signed_body lets us sign different data than we send (tampering test)."""
    timestamp = timestamp or int(time.time())
    signature = sign(secret, timestamp, signed_body if signed_body is not None else body)
    headers = {
        "Content-Type": "application/json",
        "X-Timestamp": str(timestamp),
        "X-Signature": signature,
    }
    return requests.post(f"{URL}/webhook", data=body, headers=headers)


def show(name, response, expected):
    result = "PASS" if response.status_code == expected else "FAIL"
    print(f"[{result}] {name}: got {response.status_code}, expected {expected} -> {response.text.strip()}")


# Health endpoint (no signature needed)
r = requests.get(f"{URL}/health")
show("health check", r, 200)

event_id = str(uuid.uuid4())
body = json.dumps({"id": event_id, "type": "model.registered", "model": "churn-v2"}).encode()

# 1. Valid request
show("valid signature", send(body), 200)

# 2. Same event again (idempotency)
show("duplicate event", send(body), 200)

# 3. Wrong secret
body2 = json.dumps({"id": str(uuid.uuid4()), "type": "test"}).encode()
show("wrong secret", send(body2, secret="wrong-secret"), 401)

# 4. Tampered body (signed one thing, sent another)
original = json.dumps({"id": str(uuid.uuid4()), "amount": 10}).encode()
tampered = json.dumps({"id": str(uuid.uuid4()), "amount": 9999}).encode()
show("tampered body", send(tampered, signed_body=original), 401)

# 5. Old timestamp (replay attack)
body3 = json.dumps({"id": str(uuid.uuid4()), "type": "old"}).encode()
show("old timestamp", send(body3, timestamp=int(time.time()) - 3600), 401)

# 6. Missing signature headers
r = requests.post(f"{URL}/webhook", data=body3, headers={"Content-Type": "application/json"})
show("no headers", r, 400)
