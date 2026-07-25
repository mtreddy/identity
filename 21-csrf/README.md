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

**Cross-Site Request Forgery (CSRF)** is an attack that forces an authenticated user to execute unwanted, state-changing actions on a web application where they are currently authenticated.

Based on the [21-csrf module](https://github.com/mtreddy/identity/blob/main/21-csrf/README.md) you are viewing, here is a breakdown of how the attack works and how modern applications defend against it.

### The Core Flaw: Automatic Cookie Attachment

CSRF exploits a fundamental behavior of web browsers: **browsers automatically include session cookies with requests made to a domain, regardless of where the request originated.**

Because of this, *authentication alone does not stop CSRF*. If you are logged into your bank, and you visit a malicious website in another tab, the attacker doesn't need to steal your password or read your cookie. They just need to trick your browser into sending a request to the bank.

### How the Attack Works Under the Hood

1. **The Setup:** A user logs into a vulnerable site (e.g., the `app.py` in the repo) and receives a session cookie.
2. **The Lure:** The user visits an attacker-controlled webpage while still logged in.
3. **The Forgery:** The attacker's page contains a hidden HTML form or a piece of JavaScript designed to make a cross-site `POST` request to a vulnerable endpoint on the target site (like the `POST /vuln/change-email` endpoint in the demo).
4. **The Execution:** The browser executes the request and automatically attaches the user's valid session cookie. The server sees a valid session and processes the request, changing the user's email to the attacker's email (`attacker@evil.example`).

### How the Defenses Hold

To protect endpoints (like the `/safe/change-email` route), developers use a defense-in-depth approach:

#### 1. The Synchronizer Token (CSRF Token)

This is the classic defense.

* When the server renders a legitimate web form, it embeds a cryptographically random, session-bound **CSRF token** as a hidden field.
* When the form is submitted, the server verifies that the submitted token matches the one stored in the user's session.
* **Why it works:** Because of the browser's **Same-Origin Policy**, the attacker's malicious webpage cannot read data from the legitimate site. Therefore, they cannot read the hidden CSRF token to include it in their forged POST request. The server rejects the forged request (usually with a `403 Forbidden`) because the token is missing or invalid.

#### 2. The `SameSite` Cookie Attribute

This is a newer, browser-level defense that has drastically reduced CSRF vulnerabilities.

* When the server sets the session cookie, it appends the attribute `SameSite=Lax` or `SameSite=Strict`.
* **Why it works:** This tells the browser *not* to send the session cookie on cross-site `POST` requests. If the attacker's site tries to trigger the form submission, the browser strips the session cookie away. The server receives an unauthenticated request and rejects it. As the repository notes, modern browsers default to `Lax`, meaning many CSRF attacks fail before the token is even checked.

*(Note: While these defenses stop CSRF, they do not stop Cross-Site Scripting (XSS). If an attacker can execute JavaScript directly on your legitimate domain via XSS, they can bypass both SameSite cookies and CSRF tokens by simply reading the token and making the request from the same origin.)*


