# 02 — Login + Password · Secrets & transport (secret key, debug off, TLS)

Builds directly on `../01-login-password`. **The auth logic is identical** —
this step hardens how the *server* is operated. Diff the two to see exactly
what changed:

```bash
diff -ru ../01-login-password ./ | less
```

## What we fix in this step

| # | Fix | File |
|---|-----|------|
| 1 | Secret key loaded from environment; server refuses to start without it | `app.py` (top) |
| 2 | Debug server OFF by default (opt-in, local-only) | `app.py` (`__main__`) |
| 3 | TLS/HTTPS support for the login transport | `app.py` (`__main__`) |

### 1. Secret key from the environment
**Threat: session forgery / privilege escalation.** The session cookie is
signed with `SECRET_KEY`. In the base version it was hard-coded in source, so
anyone who reads the code (leaked repo, shared sample, dependency mirror) can
compute a valid signature and forge a cookie that says `user_id = <anyone>` —
logging in as any user *without a password*. Fix: read `SECRET_KEY` from the
environment and **fail to boot** if it's missing, making a real, secret,
per-deployment key mandatory.

### 2. Debug server off by default
**Threat: remote code execution.** Flask's `debug=True` turns on the Werkzeug
interactive debugger. If an exception fires on a reachable instance, an
attacker gets an in-browser Python console running as the app. It also leaks
source and stack traces (information disclosure). Fix: `debug=False` unless you
explicitly set `FLASK_DEBUG=1` for local work.

### 3. TLS / HTTPS
**Threat: credential theft via network eavesdropping (man-in-the-middle).**
Over plain HTTP the email and password are sent in cleartext; anyone on the
path (shared Wi-Fi, a proxy, a compromised router) can read them, and can also
steal the session cookie. Fix: serve over HTTPS so the login is encrypted.
Real certs go in `TLS_CERT`/`TLS_KEY`; `USE_ADHOC_TLS=1` gives a self-signed
cert for local testing.

## Run it

```bash
cd 02-secrets-transport
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Feature 1: a secret key is now REQUIRED
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

python seed.py
python app.py                 # HTTP on 127.0.0.1:5000

# Optional — Feature 3, local HTTPS with a throwaway cert:
#   USE_ADHOC_TLS=1 python app.py     -> https://127.0.0.1:5000
# Optional — Feature 2, local debugging only:
#   FLASK_DEBUG=1 python app.py
```

Test accounts (from `seed.py`):
`alice@example.com` / `correct-horse-battery-staple` ·
`bob@example.com` / `hunter2`

## Still open (addressed in later steps)
Cookie flags, brute-force protection, timing enumeration (→ 03-auth-robustness);
CSRF, bcrypt 72-byte truncation, security headers (→ 04-web-hardening);
revocable sessions, password policy, auth logging, error pages (→ 05-defense-in-depth).
