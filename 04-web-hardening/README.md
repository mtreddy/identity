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
