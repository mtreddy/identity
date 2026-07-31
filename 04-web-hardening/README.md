# 04 — Login + Password · Web hardening (CSRF, bcrypt limit, headers)

Builds on `../03-auth-robustness`.

```bash
diff -ru ../03-auth-robustness ./ | less
```

## What we fix in this step

| # | Fix | File |
|---|-----|------|
| 7 | CSRF protection on POST forms | `app.py` (`CSRFProtect`), `templates/login.html` |
| 8 | Defeat bcrypt 72-byte truncation | `db.py` (`_prehash`) |
| 9 | Security response headers | `app.py` (`set_security_headers`) |

### 7. CSRF protection
**Threat: cross-site request forgery.** Without a token, a page on another
site can auto-submit a form to our `/login` (or, later, `/change-password`)
using the victim's cookies — e.g. "login CSRF" that silently logs the victim
into an attacker-controlled account, or state changes made on the victim's
behalf. Flask-WTF's `CSRFProtect` requires every POST to include a secret,
session-bound token rendered by `{{ csrf_token() }}`. A cross-site page can't
read that token, so forged POSTs are rejected with HTTP 400.

#### What the token actually is

Flask-WTF keeps **two** related values (see `flask_wtf/csrf.py`):

1. **Raw token** — stored server-side in the signed session cookie as
   `session["csrf_token"]`, generated once per session as
   `hashlib.sha1(os.urandom(64)).hexdigest()` → a **40-char hex** nonce. Never
   rendered raw into the page.
2. **Signed token** — what `{{ csrf_token() }}` emits into the hidden form
   field. The raw nonce is run through
   `URLSafeTimedSerializer(SECRET_KEY, salt="wtf-csrf-token")`, giving three
   URL-safe-base64 sections joined by dots:

   ```
   payload . timestamp . signature
   Ijc0MWQ4…MWQi . am0C7g . hrpF1y6C…1Fc
   ```

   - **payload** — base64 of the raw hex nonce
   - **timestamp** — issue time; drives the default **3600 s** expiry
     (`WTF_CSRF_TIME_LIMIT`)
   - **signature** — HMAC over `payload.timestamp`, keyed by `SECRET_KEY` + salt

Validation both checks the signature/age *and* compares the unwrapped payload
against `session["csrf_token"]` (constant-time). A cross-site page can neither
read the victim's session nonce nor forge the HMAC, so its POST fails — which
is why tampering with the signature is rejected exactly like a missing token
(both are asserted in `test.py`).

### 8. bcrypt 72-byte truncation
**Threat: silent password collisions / weaker-than-expected hashing.** bcrypt
ignores everything past the first 72 bytes of input. Two long passwords sharing
a 72-byte prefix hash identically and are interchangeable at login. Fix
(`db._prehash`): hash the full password with SHA-256, base64-encode it to a
fixed 44-byte value, and feed *that* to bcrypt — so every byte of the password
matters and the input is always within bcrypt's limit.

### 9. Security headers
**Threats: clickjacking, MIME-sniffing, referrer leakage, protocol downgrade.**
Every response now sets:
- `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` — can't be framed
  (clickjacking).
- `X-Content-Type-Options: nosniff` — browser won't reinterpret content types.
- `Content-Security-Policy: default-src 'self'` — restricts what the page may
  load, limiting XSS impact.
- `Referrer-Policy: no-referrer` — don't leak URLs to other sites.
- `Strict-Transport-Security` — once on HTTPS, force HTTPS thereafter.

## Flow — how the communication starts and finishes

Same login lifecycle as `../02-secrets-transport`, now with three more defenses
woven in. Communication **starts** with `GET /login`, which mints a
session-bound **CSRF token** into the form (fix #7). The `POST` back must carry
that token or it's rejected with **400** before any password check — and the
password is SHA-256 pre-hashed so bcrypt sees every byte (fix #8). **Every**
response, start to finish, is stamped with security headers (fix #9). It
**finishes** when `session.clear()` empties the cookie at logout.

```
  ┌──────────┐            ┌─────────────────────┐          ┌───────────┐
  │ Browser  │            │  Flask app (app.py) │          │ identity  │
  │          │            │   127.0.0.1:5000    │          │  .db      │
  └────┬─────┘            └──────────┬──────────┘          └─────┬─────┘
       │                             │                           │
  ═════╪═════ START: GET LOGIN FORM ═╪═══════════════════════════════════
       │                             │
       │  GET /login ───────────────►│
       │                             │  render login.html with a
       │                             │  session-bound {{ csrf_token() }} 🔒#7
       │◄─ 200 form + hidden token ──│
       │  (every response carries      X-Frame-Options, nosniff,
       │   security headers        🔒#9 CSP, Referrer-Policy, HSTS)
       │                             │
  ═════╪═════ POST CREDENTIALS ══════╪═══════════════════════════════════
       │                             │
       │  POST /login                │
       │  email + password + csrf_token►│
       │                             │  CSRFProtect: token valid &      🔒#7
       │                             │  session-bound?
       │                             │   ✘ missing/forged → 400 (CSRFError)
       │                             │      cross-site page can't read the
       │                             │      token, so login CSRF fails here
       │                             │   ✔ token ok ↓
       │                             │  rate limit 10/IP + 5/account?  🔒(#5)
       │                             │   ✘ over limit → 429
       │                             │   ✔ ↓
       │                             │  get_user_by_email(email) ──► │
       │                             │◄──────────── user row / None ──│
       │                             │  verify_password():
       │                             │  SHA-256→base64 pre-hash,then   🔒#8
       │                             │  bcrypt.checkpw (full pw counts;
       │                             │  real+dummy cost the same 🔒#6 timing)
       │                             │
       │                             │  ✔ match: session.clear();
       │                             │    session["user_id"]=…; signed
       │                             │    HttpOnly+Secure+SameSite cookie 🔒(#1,#4)
       │  302 → /dashboard           │
       │◄─ Set-Cookie: session=…sig ─│  (+ security headers 🔒#9)
       │                             │  ✘ no match → "Invalid email or
       │                             │    password." (generic, re-render)

  ═════════ AUTHENTICATED REQUEST ══════════════════════════════════════
       │                             │
       │  GET /dashboard             │
       │  Cookie: session=…sig ─────►│
       │                             │  login_required: valid session?
       │                             │  get_resources_for_user() ──► │
       │                             │◄──────────── resources ────────│
       │◄─ 200 dashboard.html ───────│  (+ security headers 🔒#9)

  ═════════ FINISH: LOGOUT ═════════════════════════════════════════════
       │                             │
       │  GET /logout ──────────────►│
       │                             │  session.clear()
       │◄─ 302 → /login; Set-Cookie: session= (empty)
       │                             │
       ▼                             ▼
   session over                 cookie invalidated
```

🔒#7/#8/#9 are this step's new fixes; 🔒(#1,#4,#5,#6) in parentheses are the
defenses carried forward from 02–03 that also act on this path. `diff -ru
../03-auth-robustness ./` and compare the Flow sections to see #7–#9 appear.

## Run it

```bash
cd 04-web-hardening
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py
USE_ADHOC_TLS=1 python app.py          # https://127.0.0.1:5000
# or HTTP smoke test: COOKIE_SECURE=0 python app.py
```

Because of Feature 7, a browser works normally (the form carries the token),
but scripted POSTs must first GET `/login`, read the `csrf_token`, and send it
back with the session cookie.

## Still open (final step)
Revocable server-side sessions, password policy, auth logging, custom error
pages (→ 05-defense-in-depth).
