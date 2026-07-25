# 16 — TOTP (time-based one-time password, 2FA)

A second factor on top of the password login (mechanism 01). The user proves
**something they know** (password) *and* **something they have** (an
authenticator app holding a shared secret) — so a stolen password alone no
longer grants access.

- **TOTP** (RFC 6238) = **HOTP** (RFC 4226) with the counter derived from the
  clock: `code = HOTP(secret, floor(unixtime / 30))`, 6 digits, SHA-1.
- Both sides hold the same Base32 **secret** (provisioned once via an
  `otpauth://` URI / QR). No code is transmitted at enrollment; each side
  computes the same code from the time.
- Implemented **from the standard library** (`hmac`, `hashlib`, `struct`) in
  `totp.py` — it's short and worth reading.

## Files

| File | Role |
|------|------|
| `totp.py` | HOTP/TOTP from primitives: `generate_secret`, `now_code`, `verify` (±window), `provisioning_uri` |
| `db.py` | users (bcrypt) + `totp_secret` / `totp_enabled` |
| `app.py` | two-step login (`/login` → `/verify`), enrollment (`/setup`), protected `/` |
| `seed.py` | demo user with TOTP enabled (prints the secret for testing) |
| `client_example.py` | drives the two-step login and the wrong-code / no-2FA cases |

## Run it

```bash
cd 16-totp
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py           # prints the TOTP secret + current code
COOKIE_SECURE=0 python app.py     # http://127.0.0.1:5000
```

Log in as `user@example.com` / `correct-horse-battery-staple`, then enter the
6-digit code (add the printed `otpauth` URI to an authenticator app, or read the
current code from `seed.py`). Headless:

```bash
TOTP_SECRET=<from seed.py> API_BASE=http://127.0.0.1:5000 python client_example.py
```

## The flow

1. **`/login`** — verify the password. If TOTP is enabled, the session is only
   *pending* (factor 1) and the user is sent to `/verify`; otherwise they're in.
2. **`/verify`** — check the 6-digit code with `totp.verify` (current step ±1 for
   clock skew, constant-time compare). On success the session becomes *full*.
3. **`/`** — the protected page requires a *full* session; a pending session
   (password only) is bounced back to `/login`.
4. **`/setup`** — enrollment: shows the secret + `otpauth` URI and requires one
   valid code to confirm the authenticator is in sync before enabling.

## Threats addressed
- **Stolen/reused password:** useless without the current TOTP code.
- **Phishing/replay within a step:** codes rotate every 30s and only ±1 step is
  accepted (small skew window).
- **Code brute force:** 6 digits ≈ 10⁶ values, so attempts are **rate-limited**
  per pending user (5 / minute here).
- **Timing leaks:** code comparison is constant-time (`hmac.compare_digest`).

## Limitations / further hardening
Encrypt the TOTP secret at rest; one-time **backup/recovery codes**; reject
reuse of a code within its 30s step (store the last accepted step);
account-lockout + alerting on repeated failures; WebAuthn/passkeys as a
phishing-resistant step up from TOTP.

**Time-Based One-Time Password (TOTP)** is a two-factor authentication (2FA) mechanism that adds a layer of security beyond a standard password. It works by requiring the user to prove they possess a specific device (like a smartphone with an authenticator app) that holds a shared secret.

Based on the [repository documentation](https://github.com/mtreddy/identity/blob/main/16-totp/README.md) you are viewing, here is a breakdown of how it works under the hood:

### 1. The Shared Secret (Enrollment)

For TOTP to work, both the server and the user's authenticator app must hold the exact same **Base32 secret key**.

* During setup, the server generates this secret and shares it with the user, typically via a QR code (which encodes an `otpauth://` URI).
* **Crucial detail:** No codes are actually transmitted over the network after this initial enrollment.

### 2. Independent Calculation

Once both sides have the secret, they can independently generate the exact same 6-digit code without communicating with each other. They do this by combining the **shared secret** with the **current time**.

TOTP (defined in RFC 6238) is essentially an HMAC-based One-Time Password (HOTP) where the counter is replaced by the current time. The formula looks like this:

$\text{code} = \text{HOTP}(\text{secret}, \lfloor \frac{\text{unixtime}}{30} \rfloor)$

* **Time Steps:** The UNIX time is divided by 30, meaning the resulting code changes exactly every 30 seconds.
* **Algorithm:** It typically uses SHA-1 to hash the secret and the time-step together, truncating the result into a user-friendly 6-digit number.

### 3. The Verification Flow

When a user attempts to log in:

1. **Factor 1:** The user enters their password. If correct, the server puts their session in a *pending* state.
2. **Factor 2:** The user opens their app, reads the current 6-digit code, and submits it.
3. **Validation:** The server calculates what the code *should* be at that exact moment using the shared secret it has on file.
4. **Clock Skew:** Because device clocks might not be perfectly synchronized, servers usually accept codes from the current 30-second step, plus or minus one step ($\pm1$).
5. **Security:** The server uses a constant-time comparison (like `hmac.compare_digest`) to check the submitted code against the expected code, which prevents attackers from guessing the code via timing attacks. If they match, the login is successful.
