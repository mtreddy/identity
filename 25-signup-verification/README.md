# 25 — Signup + Email Verification (self-service user provisioning)

Where do the users in `01`–`05` actually come from? Until now, `seed.py`. This
mechanism adds the real front door: **self-service signup**, gated by an
**email-verification** step so an account only becomes usable once its owner has
proven they control the address.

It builds on `../05-defense-in-depth` — you keep the CSRF tokens, rate limiting,
password policy, server-side revocable sessions, and auth logging, and add the
provisioning routes on top:

```bash
diff -ru ../05-defense-in-depth . 
```

This is the **Users** half of the cross-cutting provisioning story (see
`../PROVISIONING.md`); `18-scim` is the IdP-driven counterpart, and
`26-dynamic-client-registration` provisions *clients* rather than users.

## Files

| File | Role |
|------|------|
| `app.py` | `/signup`, `/verify`, `/resend`, and the login route with the **verification gate** |
| `verify.py` | verification-token primitives: high-entropy token, SHA-256 hashing, TTL |
| `mailer.py` | stubbed email delivery — writes the link to the log and `outbox.log` |
| `db.py` | adds `users.email_verified` and the single-use `email_verifications` table |
| `policy.py` | password policy (reused from 05) |
| `seed.py` | one **pre-verified** account so you can log in immediately |
| `client_example.py` | drives signup → read link → verify → login without a browser |
| `test.py` | happy path **plus** the gate, single-use, expiry, and no-enumeration checks |

## The flow

```
/signup  ──►  create unverified account  ──►  email a single-use link
                                                     │
   user clicks link  ──►  /verify?token=…  ──►  email_verified = 1
                                                     │
                              /login  ──►  (gate) allowed only if verified
```

## Threats addressed

| # | Threat | Defense |
|---|--------|---------|
| 1 | **Registering an address you don't own** (impersonation, spam signups) | Account is created `email_verified = 0` and the **login gate** refuses a session until a link emailed to the address is clicked — possession of the mailbox is the proof |
| 2 | **Verification-link leak / replay** (logs, referrer, shared link) | Token is **single-use** (one-shot `UPDATE … WHERE used = 0`) and **short-TTL** (`expires_at`); redeeming it twice or late fails |
| 3 | **Database leak → forged verifications** | Only the **SHA-256 hash** of the token is stored (high-entropy → fast hash is correct, as with API keys in `06`); the raw token exists only in the email |
| 4 | **Account enumeration at signup** | `/signup` and `/resend` return an **identical** "check your email" response whether or not the address exists; an already-registered address gets an out-of-band "you already have an account" notice instead |
| 5 | **Mail-bombing a victim's inbox** | `/resend` is rate-limited per IP *and* capped per account in the DB (`count_recent_verifications`); each new link invalidates the previous outstanding one |
| 6 | **Brute-forcing tokens / signup abuse** | High-entropy (~256-bit) tokens can't be guessed; `/signup` is rate-limited; lookups are by hash so there's no secret-dependent timing |
| 7 | **Weak passwords at the front door** | The `05` password policy (length + breached/common blocklist, NIST 800-63B) runs on signup, not just on change |

Carried over from `05`: CSRF tokens on every POST, hardened session cookie,
per-account + per-IP login rate limiting, timing-equalized login (dummy bcrypt
compare for unknown users), security headers, and auth logging that never
records a password.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export PORT=5025
export PUBLIC_BASE_URL="http://127.0.0.1:5025"   # so emailed links resolve
python seed.py
python app.py
```

Open `http://127.0.0.1:5025/signup`, register, then read the verification link
from the server log (or `outbox.log`) and open it. Or log straight in with the
seeded, pre-verified account `alice@example.com` / `correct-horse-battery-staple`.

Drive the whole thing headless:

```bash
API_BASE=http://127.0.0.1:5025 python client_example.py
python test.py          # inside the venv
```

## Limitations / further hardening

- **Email delivery is stubbed** to `outbox.log`. A real system hands off to SMTP
  or an email API and must treat the link as a bearer secret in transit and in
  logs. Consider a short numeric OTP as an alternative to a clickable link.
- **No password-reset / account-recovery** flow yet — the same single-use-token
  machinery generalizes to it (a candidate mechanism in `TODO.md`), and recovery
  is the flow attackers target most.
- **Admin / invite-based** provisioning (create → invite → first-login enrollment)
  is the other user-provisioning path, still on the backlog.
- Verification proves *control of an address at one moment*; it doesn't prove the
  address stays yours. High-value actions should still step up (see `16`/`17`).
