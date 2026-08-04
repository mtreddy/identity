# 34 — SIEM audit webhook (signed, replay-proof event delivery)

Almost every other mechanism ends its README with *"ship auth logs to alerting."*
This is that step, done safely. An app emits **structured audit events** — a
login failure, a token revocation, a role grant — by POSTing them to a webhook:
an HTTP endpoint that stands in for a **SIEM's event collector** (Splunk HEC,
Elastic, Sentinel, Datadog…). The receiver logs each accepted event to a sink.

The threat is specific to webhooks: the receiver takes **unsolicited POSTs from
the network**, so anyone who learns the URL can forge or replay events and
poison the audit trail the SIEM is meant to trust. The fix is to **sign every
event** and make the receiver verify authenticity, freshness, and uniqueness
before it stores anything. A `/vuln/ingest` twin with verification removed shows
exactly what an unauthenticated webhook lets through.

- **Sender:** `audit.py` builds + HMAC-signs events; `client_example.py` drives it
- **Receiver / “local URL”:** Flask (`app.py`), verifies and appends to a JSONL sink
- **Credential:** a 256-bit shared secret (`SIEM_SECRET`); events carry an
  `X-Siem-Signature: t=…,n=…,v1=<hmac>` header

## Files

| File                | Role                                                             |
|---------------------|------------------------------------------------------------------|
| `audit.py`          | The mechanism: `build_event`, `canonical_body`, `sign`, `verify`, `NonceCache` (and *why* HMAC, not bcrypt/JWS) |
| `app.py`            | Receiver: `/siem/ingest` (verified) vs `/vuln/ingest` (not); `/siem/events` reads a sink back |
| `seed.py`           | Mints the shared `SIEM_SECRET` (printed once)                    |
| `client_example.py` | Sender: emits valid events, then a tampered / replayed / unsigned one |
| `test.py`           | Happy path + the negatives (bad sig, wrong key, stale ts, replay, vuln accepts forgery) |

## Run it

```bash
cd 34-siem-audit-webhook
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py                     # prints:  export SIEM_SECRET="..."
export SIEM_SECRET="...paste it..." # the receiver AND sender share this
python app.py                      # receiver on http://127.0.0.1:5000
```

In another shell (same `SIEM_SECRET` exported):

```bash
python client_example.py           # emits valid events, then forgery/replay attempts
curl "http://127.0.0.1:5000/siem/events"          # what the SIEM stored (accepted only)
curl "http://127.0.0.1:5000/siem/events?sink=vuln" # what the unverified endpoint swallowed
```

Sending one event by hand shows the wire format:

```bash
# The signature must cover the EXACT bytes you send, so build them once.
BODY='{"actor":"alice","event":"auth.login.failed","id":"evt_1","outcome":"failure","ts":"2026-08-03T00:00:00Z","detail":{}}'
TS=$(date +%s); N=$(python -c 'import secrets;print(secrets.token_urlsafe(16))')
SIG="t=$TS,n=$N,v1=$(python -c "import hmac,hashlib,os,sys;print(hmac.new(os.environ['SIEM_SECRET'].encode(), f'$TS.$N.'.encode()+sys.argv[1].encode(), hashlib.sha256).hexdigest())" "$BODY")"
curl -X POST http://127.0.0.1:5000/siem/ingest -H "X-Siem-Signature: $SIG" -d "$BODY"   # 202
curl -X POST http://127.0.0.1:5000/siem/ingest                          -d "$BODY"      # 401 missing-signature
```

## How the mechanism works

1. **Build** (`build_event`) — a structured event: `id`, UTC `ts`, dotted
   `event` type, `actor`, `outcome`, and event-specific `detail` (never a
   password or full secret — audit logs are read widely).
2. **Canonicalize** (`canonical_body`) — serialize to deterministic bytes
   (sorted keys, no spaces). These bytes are **both signed and sent**.
3. **Sign** (`sign`) — pick a `ts` and random `nonce`; compute
   `HMAC-SHA256(secret, "<ts>.<nonce>." + body)`; send it as
   `X-Siem-Signature: t=<ts>,n=<nonce>,v1=<hex>`. Binding `ts` and `nonce` *into*
   the MAC means an attacker can't rewrite them to dodge the later checks.
4. **Verify** (`verify`, on the receiver) over the **raw received bytes**, in order:
   signature (constant-time) → timestamp within ±tolerance → nonce unseen.
   The signature is checked *first* precisely because it authenticates the `ts`
   and `nonce` the other two checks rely on.
5. **Store** — only accepted events are appended to `siem.log`; rejects are
   logged with a reason to `receiver.log` and never touch the trusted sink.

### Why the raw bytes, not a re-parse
The receiver signs `request.get_data()` exactly as it arrived — it never
re-serializes the JSON. Re-encoding can change bytes (key order, spacing,
unicode escaping); a **canonicalization mismatch is the classic
signature-verification bug** (the same trap SAML hits in `14-saml`, which is why
that one delegates canonicalization to `signxml`).

### Why HMAC here, not bcrypt or a public-key signature
The secret is 256 bits of randomness, so a **fast keyed hash** (HMAC-SHA256) is
correct — it can't be brute-forced at any speed, and per-event verification stays
cheap. bcrypt is for *low-entropy* human passwords (`01`, `06`). HMAC is
symmetric, which fits a **point-to-point** webhook where sender and receiver can
share a secret; when many independent receivers must verify without a signing
secret, switch to an asymmetric **JWS** signature (the `07-jwt` / `10-oidc`
model) — same design axis as API keys → signed JWTs.

## Threats addressed

- **Forged events (audit poisoning):** an unsigned or wrong-key POST is rejected
  (`missing-signature` / `bad-signature`); it never reaches the sink. `/vuln`
  shows the alternative — `role.granted admin` written by anyone.
- **Tampering in transit:** the HMAC covers the whole body, so a single changed
  byte fails verification (`bad-signature`).
- **Replay:** a captured-but-valid event is stopped two ways — a **timestamp**
  window (`stale-timestamp`) bounds how long it's viable, and a remembered
  **nonce** (`replayed-nonce`, cf. DPoP's `jti` in `13`) rejects it even once
  inside that window.
- **Confidentiality / interception:** the shared secret authenticates every
  event, so the webhook **must** run over TLS (`USE_ADHOC_TLS=1` locally, or
  `TLS_CERT`/`TLS_KEY`).
- **Silent gaps:** every accept and reject is logged with a non-sensitive reason
  code, so a spike in rejects is itself a signal.

## Limitations / further hardening

- **In-memory nonce cache:** replay protection is per-process. Across multiple
  receiver instances, share the nonce store (e.g. Redis with a TTL = the
  freshness window) or the same capture replays to a different instance.
- **No delivery guarantees:** a real emitter needs **retries with backoff**, an
  idempotency key (we have `id`), and a dead-letter queue — audit events must not
  be silently dropped. This demo emits synchronously.
- **Shared-secret rotation:** rotate `SIEM_SECRET` by accepting an old and new
  key during an overlap window (the `v1=` scheme tag also lets you roll the MAC
  algorithm). For many-receiver fan-out, move to **JWS** so receivers verify
  with a public key and hold no signing secret.
- **Backpressure:** no rate limit on the ingest path; add one so a flood can't
  exhaust the sink or the nonce cache.
