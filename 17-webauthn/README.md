# 17 — WebAuthn / passkeys (phishing-resistant login)

Public-key authentication in the browser (W3C WebAuthn / FIDO2). The user's
device holds a **private key**; the server stores only the **public key**. To
log in, the device **signs a challenge** — nothing phishable is ever transmitted
or stored. This is the step up from TOTP (16): a fake site can relay a typed
6-digit code, but it can't produce a signature bound to the real origin.

- **Passkey** = a WebAuthn credential (often synced across your devices).
- **No passwords, no shared secrets** — a DB leak reveals only public keys.
- Verification is **hand-rolled on `cryptography`**; `cbor2` only decodes the
  CBOR/COSE binary structures (the non-security-critical part).

## The two ceremonies (each is begin → finish)

| | Registration (attestation) | Authentication (assertion) |
|--|--|--|
| Client makes | a new keypair for this site | a signature over the challenge |
| Returns | `attestationObject` (has the public key) | `authenticatorData` + `signature` |
| Server does | store public key + credential ID + counter | verify signature vs stored key |

What's signed/checked is the point:
- **`clientDataJSON.origin`** must equal this site's origin, and
  **`authenticatorData.rpIdHash`** must equal `SHA-256(RP ID)` → **phishing
  resistance** (a look-alike domain can't get a usable signature).
- the signature covers `authenticatorData || SHA-256(clientDataJSON)`.
- the authenticator's **sign counter** must strictly increase → **clone
  detection**.

## Files

| File | Role |
|------|------|
| `webauthn.py` | ceremony logic + signature verification; COSE↔EC; shared `build_*` (authenticator) and `verify_*` (server) |
| `db.py` | users + `credentials` (credential ID, COSE public key, sign counter) |
| `app.py` | `/register/begin·finish`, `/login/begin·finish`, browser page |
| `client_example.py` | a **software authenticator** (does what a device does) + attack demos |
| `templates/index.html` | real browser passkey UI (`navigator.credentials.*`) |

## Run it

```bash
cd 17-webauthn
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py            # http://localhost:5000
```

**Browser:** open `http://localhost:5000/` (browsers treat `localhost` as a
secure context, so WebAuthn works without TLS), enter an email, click *Register
a passkey* (Touch ID / security-key prompt), then *Sign in with passkey*.

**Headless** (software authenticator drives the same endpoints):

```bash
ORIGIN=http://localhost:5000 API_BASE=http://localhost:5000 python client_example.py
```

> The RP ID is `localhost` and the expected origin is `http://localhost:5000`
> (`RP_ID` / `ORIGIN` env vars). WebAuthn binds credentials to the RP ID, so the
> origin must match exactly.

## Threats addressed
| Threat | Defense |
|--------|---------|
| Password/secret theft or DB leak | there is no secret — only public keys are stored |
| **Phishing / relay** (the TOTP gap) | origin + RP-ID hash are signed and checked |
| Signature/response tampering | signature verified against the stored public key |
| Credential cloning | sign counter must strictly increase |
| Replay of a login | each login uses a fresh server challenge (bound in the signature) |

## Notes & further hardening
This accepts `attestation: "none"` (typical for passkeys) — enterprises can
verify attestation to require specific authenticator models. Also worth adding:
require **user verification** (UV flag) for high-value actions; store a per-user
**user handle** and support **discoverable credentials** for usernameless login;
gate registration behind an existing authenticated session; and rate-limit
`/login/begin`. Production servers typically use a maintained library
(`python-fido2`, `py_webauthn`) — here we implement it to show the mechanics.
