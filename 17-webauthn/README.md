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



**WebAuthn (Web Authentication)**, often referred to by the consumer-friendly term **Passkeys**, is a W3C and FIDO Alliance specification for passwordless authentication. Instead of relying on shared secrets (like passwords or TOTP seeds), it uses **public-key cryptography** to verify identities.

Based on the [identity/17-webauthn/README.md](https://github.com/mtreddy/identity/tree/main/17-webauthn) file you are viewing and the WebAuthn specification, here is how the mechanics and provisioning work under the hood.

### 1. Provisioning / Registration (The "Attestation" Ceremony)

Provisioning in WebAuthn is the process of generating a brand new credential (keypair) and registering its public component with the server. This is known as the **Attestation** phase.

Here is the step-by-step flow of how a key is provisioned:

1. **The Challenge:** The server generates a random, cryptographically secure challenge and sends it to the browser, along with information about the Relying Party (the website's domain or "RP ID") and the user.
2. **Key Generation:** The browser calls the `navigator.credentials.create()` API. The user's authenticator (e.g., Apple's Secure Enclave, Android's TEE, Windows Hello, or a YubiKey hardware token) prompts the user for physical verification (FaceID, TouchID, PIN).
3. **The Keypair:** Once verified, the authenticator generates a unique public-private keypair specifically bound to that website's exact domain.
4. **The Attestation Object:** The authenticator signs the server's challenge using the new private key and packages the new **Public Key** into an `attestationObject`.
5. **Server Storage:** The browser sends this data back to the server. The server verifies the attestation and extracts the Public Key. It stores *only* the Public Key, the generated Credential ID, and a sign counter in its database.
**Crucial Detail:** The private key never leaves the authenticator's secure hardware. If the server's database is breached, the attacker only gets useless public keys.

### 2. Login / Authentication (The "Assertion" Ceremony)

When the user returns to log in, they go through the **Assertion** phase.

1. **The Challenge:** The server sends a fresh, random challenge down to the browser.
2. **The Signature:** The browser calls `navigator.credentials.get()`. The authenticator prompts the user for biometrics/PIN. Once verified, it uses the securely stored private key to generate a cryptographic signature over the server's challenge.
3. **The Assertion Data:** The authenticator packages this signature and metadata into an `authenticatorData` object and returns it.
4. **Server Verification:** The server retrieves the user's stored Public Key from the database and uses it to verify the signature on the challenge. If the math checks out, the user is authenticated.

### Under-the-Hood Security Mechanisms

WebAuthn relies on strict browser-level and cryptographic checks to prevent attacks:

* **Inherent Phishing Resistance:** During both ceremonies, the browser automatically captures the exact URL the user is visiting and hashes it (`authenticatorData.rpIdHash`). The signature generated by the private key covers this origin. If a user is tricked into visiting a look-alike domain (e.g., `evil-bank.com`), the browser will refuse to use the credential registered for `bank.com`. A relayed, intercepted signature is useless.
* **Clone Detection:** Authenticators maintain a "sign counter" that strictly increases with every authentication. If the server sees a counter that is lower than or equal to the last recorded value, it indicates the private key might have been cloned, and the login can be flagged or blocked.
* **Replay Protection:** Because every authentication attempt requires the authenticator to sign a *freshly generated* challenge from the server, an attacker cannot intercept a valid login packet and reuse it later.
