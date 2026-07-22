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
