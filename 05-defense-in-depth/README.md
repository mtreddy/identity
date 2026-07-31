# 05 — Login + Password · Defense in depth (sessions, policy, logging, errors)

Final hardening step. Builds on `../04-web-hardening`.

```bash
diff -ru ../04-web-hardening ./ | less
```

A protected **`/change-password`** route is added so the new session and
password-policy features are actually exercised.

## What we fix in this step

| # | Fix | File |
|---|-----|------|
| 10 | Server-side, revocable sessions ("log out everywhere") | `app.py` (`Session`, `login_required`, epoch), `db.py` (`session_epoch`) |
| 11 | Password policy (length + breached/common rejection) | `policy.py`, `/change-password` |
| 12 | Authentication logging (never logs the password) | `app.py` (`auth_log`) |
| 13 | Custom error pages | `app.py` (`errorhandler`), `templates/404.html`, `500.html` |

### 10. Revocable server-side sessions
**Threats: no revocation, lingering sessions after compromise.** In plain
Flask the whole session lives in the signed cookie, so the server can't cancel
it — a stolen session, or one that should die when the password changes, stays
valid until it expires. Here session data is stored **server-side**
(`Flask-Session`, filesystem), and each user row has a `session_epoch`.
`login_required` checks the session's epoch against the DB on every request;
`update_password` bumps the epoch, instantly invalidating **all other**
sessions while keeping the current one. That's "log out everywhere," the
correct response to a password change or account compromise.

### 11. Password policy
**Threats: weak and breached passwords.** Following NIST SP 800-63B, we require
length (≥12) over composition tricks and reject common/breached passwords
(`policy.py`). The local blocklist stands in for a real check against Have I
Been Pwned's Pwned-Passwords range API (k-anonymity — you never send the full
password/hash), which a networked deployment should use.

### 12. Authentication logging
**Threats: undetected brute-force / account takeover.** Login successes and
failures, and password changes, are written to `auth.log` with email, source
IP, and outcome — and **never** the password. This is what lets you *detect*
the attacks the rate limiter (03-auth-robustness) is throttling; in production it feeds
a SIEM/alerting pipeline.

### 13. Custom error pages
**Threat: information disclosure.** Default framework error pages can leak
stack traces, file paths, and versions. With `debug=False` plus explicit
`404`/`500` handlers, users get a clean page and the details stay in the logs.

## Flow — how the communication starts and finishes

The big change from `../04-web-hardening` is *where the session lives*. The
cookie now holds only an **opaque session id** (fix #10); the real session data
sits **server-side** in `.flask_session`, and each user row carries a
`session_epoch`. `login_required` re-checks that epoch against the DB on **every**
request — so bumping it (on password change) instantly logs out every *other*
device. Below, Device A changes its password and Device B's next request dies.
Every auth event is logged (#12), never the password; errors render clean pages
(#13).

```
 ┌─────────┐ ┌─────────┐   ┌──────────────────┐  ┌──────────┐ ┌────────┐ ┌────────┐
 │Browser A│ │Browser B│   │ Flask app (app.py)│  │.flask_   │ │identity│ │auth.log│
 │(device) │ │(device) │   │  127.0.0.1:5000   │  │ session  │ │  .db   │ │        │
 └────┬────┘ └────┬────┘   └─────────┬─────────┘  └────┬─────┘ └───┬────┘ └───┬────┘
      │           │                  │                 │           │          │
 ═════╪═══════════╪═ START: LOGIN (both devices) ══════╪═══════════╪══════════╪═════
      │           │                  │                 │           │          │
      │ POST /login (email+pw+csrf) ►│                 │           │          │
      │           │                  │ verify_password (bcrypt) ──────────►   │
      │           │                  │◄──── user row + session_epoch ─────    │
      │           │                  │ store session DATA ────────►│          │
      │           │                  │ session["epoch"]=epoch  🔒#10          │
      │           │                  │ log "login success" ─────────────────► │ #12
      │◄─ 302 + Set-Cookie: session=<opaque id> (HttpOnly/Secure/SameSite) 🔒#10│
      │           │ (B logs in the same way; both share session_epoch = N)   │
      │           │                  │                 │           │          │

 ═════╪═ AUTHENTICATED REQUEST: epoch re-checked every time ═══════════════════════
      │           │                  │                 │           │          │
      │ GET /dashboard (opaque id)  ►│ load session ◄──│           │          │
      │           │                  │ login_required: session.epoch == DB.epoch?
      │           │                  │   get_user_by_id ─────────────────►    │
      │           │                  │   N == N ✔ → serve                     │
      │◄─ 200 dashboard.html ────────│  (+ security headers)                  │

 ═════╪═ FIX #10 IN ACTION: change password → "log out everywhere" ════════════════
      │           │                  │                 │           │          │
      │ POST /change-password       ►│                 │           │          │
      │ (current+new+csrf)           │ verify current pw ────────────────►    │
      │           │                  │ policy.validate_password(new)   🔒#11  │
      │           │                  │  (≥12 chars, not breached/common)      │
      │           │                  │  ✘ weak → error, no change             │
      │           │                  │  ✔ update_password: epoch N→N+1 ──►    │ (DB)
      │           │                  │ session["epoch"]=N+1 (A stays valid)   │
      │           │                  │ log "password changed" ──────────────► │ #12
      │◄─ "all other sessions logged out" ─────────────────────────────────── │
      │           │                  │                 │           │          │
      │           │ GET /dashboard (opaque id, epoch=N) ►│         │          │
      │           │                  │ login_required: N == N+1 ? ✘  🔒#10    │
      │           │                  │ session.clear() → redirect             │
      │           │◄─ 302 /login ────│  (B is logged out everywhere)          │

 ═════╪═ ERRORS & FINISH ════════════════════════════════════════════════════════
      │           │                  │                 │           │          │
      │ bad/expired CSRF, 429, 404, 500 → clean template, details to log 🔒#13 │
      │ GET /logout ────────────────►│ session.clear() (+ drop server data) ─►│
      │◄─ 302 /login; Set-Cookie: session= (empty) ──────────────────────────  │
      ▼           ▼                  ▼                 ▼           ▼          ▼
  session over  logged out       (opaque id now       server-side session dropped
                everywhere        maps to nothing)
```

🔒#10–#13 are this step's fixes; carried-forward defenses (TLS, cookie flags,
CSRF, rate limit, bcrypt pre-hash, headers) still apply on every arrow. `diff
-ru ../04-web-hardening ./` and compare the Flow sections.

## Run it

```bash
cd 05-defense-in-depth
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py
USE_ADHOC_TLS=1 python app.py          # https://127.0.0.1:5000
# or HTTP smoke test: COOKIE_SECURE=0 python app.py
```

Log in, open **Change password**. Note the seed passwords intentionally violate
the new policy, so you must choose a strong new one (≥12 chars, not common).
Watch `auth.log` for the recorded events. To see the 500 page, start with
`TEST_ERRORS=1 ... python app.py` and visit `/__boom`.

## Where this leaves us
This is a solid password-login baseline. The natural *next mechanisms* in the
series (new top-level dirs) build on identity rather than harden it further:
signup + email verification + password reset, TOTP/2FA, API keys / JWT for
machine clients, OAuth2, and WebAuthn/passkeys.
