# 03 — Login + Password · Auth robustness (cookie flags, rate limiting, timing)

Builds on `../02-secrets-transport` (which already added the env
secret key, debug-off, and TLS). This step strengthens the **authentication
mechanism itself**.

```bash
diff -ru ../02-secrets-transport ./ | less
```

## What we fix in this step

| # | Fix | File |
|---|-----|------|
| 4 | Hardened session cookie: `Secure`, `HttpOnly`, `SameSite`, expiry | `app.py` (`app.config`) |
| 5 | Brute-force / credential-stuffing protection (rate limiting) | `app.py` (`@limiter.limit`) |
| 6 | Close login timing side-channel (user enumeration) | `app.py` (`_DUMMY_HASH`) |

### 4. Hardened session cookie
**Threats: session hijacking, XSS cookie theft, CSRF, unbounded session life.**
- `HttpOnly` — scripts can't read the cookie, so an XSS bug can't exfiltrate it.
- `Secure` — the browser only sends it over HTTPS, so it can't leak on plain HTTP.
- `SameSite=Lax` — the cookie isn't attached to cross-site requests, blunting CSRF.
- `PERMANENT_SESSION_LIFETIME` — sessions expire, limiting how long a stolen or
  forgotten session stays valid.

### 5. Brute-force protection (rate limiting)
**Threats: password brute-forcing and credential stuffing.** The base version
accepted unlimited guesses, so an attacker could try millions of passwords, or
replay leaked username/password pairs at scale. We cap login POSTs **per IP**
(10/min) *and* **per account email** (5/min) — the per-account limit stops an
attacker who rotates IPs from hammering one victim. Exceeding a limit returns
HTTP 429 with a friendly retry message.
(In-memory counters here; use a shared store like Redis in production.)

### 6. Timing side-channel / user enumeration
**Threat: account enumeration.** The base code only ran bcrypt when the user
existed, so "no such user" returned faster than "wrong password." By measuring
response time an attacker learns which emails are registered — useful for
targeted phishing or focused brute-forcing. Fix: **always** perform one bcrypt
verification, against a fixed dummy hash when the account doesn't exist, so both
paths cost the same. (The generic error text already avoided leaking it in
words; this closes the timing leak.)

## Flow — how the communication starts and finishes

Same login lifecycle as `../02-secrets-transport`; this step hardens the
`POST /login` handler itself. Two **rate limiters** gate the POST — 10/min per IP
*and* 5/min per account email (#5) — before any password work. Then **one** bcrypt
verification always runs, against a dummy hash when the email is unknown, so
"no such user" and "wrong password" take the same time (#6). On success the
signed cookie is set with `HttpOnly`/`Secure`/`SameSite` + a bounded lifetime
(#4). It **finishes** at logout with `session.clear()`.

```
  ┌──────────┐            ┌─────────────────────┐          ┌───────────┐
  │ Browser  │            │  Flask app (app.py) │          │ identity  │
  │          │            │   127.0.0.1:5000    │          │  .db      │
  └────┬─────┘            └──────────┬──────────┘          └─────┬─────┘
       │                             │                           │
  ═════╪═════ START: TLS + GET LOGIN ╪═══════════════════════════════════
       │  TLS handshake ◄═══════════►│  (from 02)                │
       │  GET /login ───────────────►│                           │
       │◄──────── 200 login.html ────│                           │
       │                             │                           │
  ═════╪═════ POST CREDENTIALS ══════╪═══════════════════════════════════
       │  POST /login (email+pw) ───►│                           │
       │                             │  rate limit: 10/min per IP  🔒#5
       │                             │           +  5/min per email 🔒#5
       │                             │   ✘ over limit → 429 "Too many attempts"
       │                             │   ✔ under limit ↓          │
       │                             │  get_user_by_email(email) ──► │
       │                             │◄──── user row OR None ─────────│
       │                             │  stored_hash = user's hash    │
       │                             │    OR _DUMMY_HASH if None  🔒#6
       │                             │  verify_password() — ALWAYS one
       │                             │  bcrypt (both paths cost the same)
       │                             │
       │                             │  ✔ user AND password_ok:
       │                             │    session.clear(); set user_id;
       │                             │    cookie: HttpOnly+Secure+     🔒#4
       │                             │    SameSite=Lax, 30-min lifetime
       │  302 → /dashboard           │
       │◄─ Set-Cookie: session=…sig ─│
       │                             │  ✘ else → "Invalid email or password."
       │                             │    (same generic text, same timing)

  ═════════ AUTHENTICATED REQUEST ══════════════════════════════════════
       │  GET /dashboard (cookie) ──►│ login_required: user_id in session?
       │                             │ get_resources_for_user() ──► │
       │◄──────── 200 dashboard.html │◄─────────── resources ─────────│

  ═════════ FINISH: LOGOUT ═════════════════════════════════════════════
       │  GET /logout ──────────────►│ session.clear()
       │◄─ 302 /login; Set-Cookie: session= (empty)
       ▼                             ▼
   session over               cookie invalidated
```

🔒#4–#6 are this step's fixes; TLS + secret-key/debug-off carry forward from 02.
`diff -ru ../02-secrets-transport ./` and compare the Flow sections.

## Run it

```bash
cd 03-auth-robustness
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py

# Over HTTPS (recommended — Secure cookies work):
USE_ADHOC_TLS=1 python app.py          # https://127.0.0.1:5000

# Over plain HTTP for a quick test, relax the Secure flag so the cookie is sent:
# COOKIE_SECURE=0 python app.py
```

> `SESSION_COOKIE_SECURE` defaults to **on**. A Secure cookie is not sent over
> plain HTTP, so for an HTTP-only smoke test set `COOKIE_SECURE=0`. Leave it on
> (the default) whenever you serve over TLS.

## Still open (later steps)
CSRF tokens, bcrypt 72-byte truncation, security headers (→ 04-web-hardening);
revocable server-side sessions, password policy, auth logging, error pages
(→ 05-defense-in-depth).
