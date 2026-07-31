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

## Flow — how the communication starts and finishes

Communication **starts** with a TLS handshake (fix #3), so the password never
travels in cleartext. The **signed session cookie** (fix #1) is the thread that
carries identity across requests — unforgeable without `SECRET_KEY`. It
**finishes** when `session.clear()` empties that cookie at logout.

```
  ┌──────────┐            ┌─────────────────────┐          ┌───────────┐
  │ Operator │            │  Flask app (app.py) │          │ identity  │
  │  / shell │            │   127.0.0.1:5000    │          │  .db      │
  └────┬─────┘            └──────────┬──────────┘          └─────┬─────┘
       │                             │                           │
  ═════╪═════ BOOT / PROVISIONING ═══╪═══════════════════════════╪═══════
       │                             │                           │
       │ export SECRET_KEY=…    🔒#1 │                           │
       │ python seed.py ────────────────── create users ───────► │ bcrypt
       │                             │                           │ hashes
       │ python app.py ─────────────►│                           │
       │                             │ read SECRET_KEY from env  │
       │                             │ (no key → refuse to boot) │
       │                             │ debug=False by default🔒#2│
       │                             │ ssl_context set        🔒#3
       │        listening on HTTPS   │                           │

  ┌──────────┐                       │
  │ Browser  │                       │
  └────┬─────┘                       │
       │                             │
  ═════╪═════ START: TLS + LOGIN ════╪═══════════════════════════════════
       │                             │
       │  TLS handshake         🔒#3 │   ← encrypts everything below, so
       │◄═══════════════════════════►│     password + cookie can't be
       │  (cert from TLS_CERT/KEY    │     read on the wire (MITM)
       │   or USE_ADHOC_TLS)         │
       │                             │
       │  GET /login ───────────────►│
       │◄──────── 200 login.html ────│
       │                             │
       │  POST /login                │
       │  email + password (in TLS) ►│
       │                             │  get_user_by_email(email) ──► │
       │                             │◄───────────── user row ────────│
       │                             │  verify_password()
       │                             │  bcrypt.checkpw (constant-time)
       │                             │
       │                             │  ✔ match: session.clear();
       │                             │    session["user_id"]=…;
       │                             │    cookie SIGNED w/ SECRET_KEY🔒#1
       │  302 → /dashboard           │
       │◄─ Set-Cookie: session=…sig ─│
       │                             │  ✘ no match → "Invalid email or
       │                             │    password." (re-render form)

  ═════════ AUTHENTICATED REQUEST ══════════════════════════════════════
       │                             │
       │  GET /dashboard             │
       │  Cookie: session=…sig ─────►│
       │                             │  verify cookie signature
       │                             │  with SECRET_KEY          🔒#1
       │                             │  (forged/tampered → rejected;
       │                             │   login_required → redirect)
       │                             │  get_resources_for_user() ──► │
       │                             │◄──────────── resources ────────│
       │◄──────── 200 dashboard.html │

  ═════════ FINISH: LOGOUT ═════════════════════════════════════════════
       │                             │
       │  GET /logout ──────────────►│
       │                             │  session.clear()
       │◄─ 302 → /login; Set-Cookie: session= (empty)
       │                             │
       ▼                             ▼
   session over                 cookie invalidated
```

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

## Provisioning — what must exist before first run

This is the first step that can't just be `python app.py`'d: fix #1 makes a real
secret a **hard prerequisite** (the server raises and exits if `SECRET_KEY` is
unset). Three things have to be provisioned first, one per layer in the
repo-wide [PROVISIONING.md](../PROVISIONING.md):

| What | Layer | Why it's needed | Demo source | Production source |
|------|-------|-----------------|-------------|-------------------|
| **`SECRET_KEY`** | server secret | signs the session cookie; app **refuses to boot** without it (fix #1) | `bootstrap.py` or a hand-exported `token_hex(32)` | secret manager (Vault/KMS), one per deployment, rotated |
| **Users + `identity.db`** | users | something to authenticate as | `seed.py` creates the DB, `alice`/`bob`, and their resources | self-service [`25-signup-verification`](../25-signup-verification/) or admin/invite |
| **TLS cert + key** | server material | encrypts the login transport (fix #3) — *optional* for a local smoke test | `USE_ADHOC_TLS=1` (throwaway self-signed) | real cert in `TLS_CERT`/`TLS_KEY` (mkcert / ACME / internal CA), rotated |

`SECRET_KEY` is *server-held* material: provision it, never hard-code or commit
it — that hard-coding is exactly the threat fix #1 removes. The repo tool writes
a strong value into a gitignored `.dev-secrets.env` (mode `0600`) so you don't
invent one by hand:

```bash
python ../bootstrap.py 02        # writes SECRET_KEY → 02-secrets-transport/.dev-secrets.env
source .dev-secrets.env          # load it into the shell
python seed.py                   # create identity.db + sample users
python app.py                    # boots (add USE_ADHOC_TLS=1 for HTTPS)
```

The DB schema and sample users stay with `seed.py` (that's this step's Layer-1
provisioning); only the server secret moves to `bootstrap.py`, because *issuance*
of the other material is itself the lesson in later mechanisms. See
[PROVISIONING.md](../PROVISIONING.md) for how every mechanism's prerequisites map
to a production source.

## Still open (addressed in later steps)
Cookie flags, brute-force protection, timing enumeration (→ 03-auth-robustness);
CSRF, bcrypt 72-byte truncation, security headers (→ 04-web-hardening);
revocable sessions, password policy, auth logging, error pages (→ 05-defense-in-depth).
