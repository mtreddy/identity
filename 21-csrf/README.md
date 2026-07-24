# 21 — CSRF attack vs. defense

A cross-cutting web-security demo (same `vuln`-vs-`safe` style as
`20-sql-injection`). **CSRF** (Cross-Site Request Forgery) tricks a logged-in
user's browser into making a state-changing request the user didn't intend —
the browser **auto-attaches the session cookie**, so the forged request is
authenticated even though it originates from an attacker's page.

Here a logged-in user's "change my email" action is exposed two ways:

| Endpoint | Protection |
|----------|-----------|
| `POST /vuln/change-email` | **none** — forgeable across sites |
| `POST /safe/change-email` | **synchronizer CSRF token** (Flask-WTF) |

> `/vuln` is intentionally exploitable — a sandbox for learning the defense.

## Files

| File | Role |
|------|------|
| `app.py` | login + the two change-email endpoints + an `/attacker` page |
| `templates/dashboard.html` | the account page with an unprotected and a protected form |
| `templates/attacker.html` | stands in for a malicious page on another origin; auto-submits a cross-site POST |
| `client_example.py` | headless simulation of the attack (a cookie-jar "browser") |

## Run it

```bash
cd 21-csrf
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
COOKIE_SECURE=0 python app.py            # http://127.0.0.1:5000

# in another shell — watch the forged request succeed on /vuln, fail on /safe:
python client_example.py
```

In a browser: open `/`, click **Sign in as Alice**, then **Open the attacker
page** — the attacker page auto-submits a hidden cross-site form and (via the
unprotected endpoint) changes your account email to `attacker@evil.example`.

## Why it works, and why the defense holds
- CSRF relies on the browser **automatically sending the session cookie** to the
  target origin. The attacker doesn't need to read anything — they just cause a
  request. So *authentication alone doesn't stop CSRF.*
- The **synchronizer token** does: `/safe` requires a secret, session-bound
  `csrf_token` rendered into the real form. A cross-site page can't read it (the
  same-origin policy stops it), so a forged POST is rejected with **403**.

## The three defenses (all used elsewhere in this repo)

| Defense | Where | What it does |
|---------|-------|--------------|
| **Synchronizer token** | this demo's `/safe`; also `04`, `05`, `09`, `10`, `16`, `19` | a secret per-session token the real form carries and a cross-site page can't |
| **`SameSite` cookie** | this demo (default `Lax`); `03`+ | the browser won't send the session cookie on a cross-site POST at all |
| **OAuth `state`** | `09`, `10`, `19` | the redirect-flow analog — a random value checked on the callback |

### The SameSite nuance (worth understanding)
`SESSION_COOKIE_SAMESITE` defaults to **`Lax`**, and a modern browser with a Lax
cookie **already blocks** the cross-site POST in the attacker page — so in a real
browser the `/vuln` attack fails on SameSite grounds before the token even
matters. To see the **token** as the deciding defense (simulating a legacy or
deliberately relaxed cookie), run:

```bash
COOKIE_SAMESITE=None python app.py
```

The headless `client_example.py` sends the cookie explicitly (as a jar-backed
client), which models the browser's auto-send regardless of SameSite — so it
isolates the **token** defense: `/vuln` succeeds, `/safe` returns 403.

## Threats addressed
| Threat | Defense |
|--------|---------|
| Forged state-changing request from another site | synchronizer token on `/safe` (403 without it) |
| Cookie sent on cross-site requests | `SameSite` attribute |
| Forgery of the OAuth redirect | `state` (see mechanism 09) |

## Notes / further hardening
Prefer `SameSite=Lax` (or `Strict`) **and** tokens (defense in depth); use
per-request or per-session tokens; consider the `Origin`/`Referer` header check
as an additional signal; and mark cookies `HttpOnly` (done here) so an XSS can't
read them — though note XSS defeats CSRF tokens too, so also fix XSS (see the
planned `22-xss`).
