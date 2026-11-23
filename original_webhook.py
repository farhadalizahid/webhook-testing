import hashlib
import hmac
import os
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

# Secret comes from the environment, never from the code
SECRET = os.environ.get("WEBHOOK_SECRET")
if not SECRET:
    raise SystemExit("Set WEBHOOK_SECRET first: export WEBHOOK_SECRET=...")
SECRET = SECRET.encode()

MAX_AGE_SECONDS = 300      # reject requests older than 5 minutes (replay protection)
seen_ids = set()           # processed event IDs (idempotency); use a database in production


@app.route("/health", methods=["GET"])
def health():
    # Open endpoint: no signature needed, returns nothing sensitive
    return jsonify(status="ok")


@app.route("/webhook", methods=["POST"])
def webhook():
    body = request.get_data()  # RAW body, needed for the HMAC
    signature = request.headers.get("X-Signature", "")
    timestamp = request.headers.get("X-Timestamp", "")

    # 1. Timestamp check
    try:
        ts = int(timestamp)
    except ValueError:
        return jsonify(error="missing or bad timestamp"), 400
    if abs(time.time() - ts) > MAX_AGE_SECONDS:
        return jsonify(error="request too old"), 401

    # 2. Signature check (constant-time comparison)
    signed_payload = timestamp.encode() + b"." + body
    expected = "sha256=" + hmac.new(SECRET, signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify(error="invalid signature"), 401

    # 3. Parse the payload (only after the signature is verified)
    event = request.get_json(silent=True)
    if not event or "id" not in event:
        return jsonify(error="invalid payload"), 400

    # 4. Idempotency: skip events we already processed
    if event["id"] in seen_ids:
        return jsonify(status="duplicate, ignored"), 200
    seen_ids.add(event["id"])

    print("Processing event:", event)
    return jsonify(status="processed"), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
