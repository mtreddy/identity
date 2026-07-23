# 14 — SAML 2.0 Web Browser SSO

The enterprise-federation counterpart to OpenID Connect (10). A user
authenticates once at an **Identity Provider (IdP)** and is admitted to a
**Service Provider (SP)** via a **signed XML assertion** passed through the
browser. Where OIDC uses signed JSON (JWT), SAML uses signed XML (XML-DSig) and
X.509 certificates in metadata.

- **Assertion:** an XML statement about the user (NameID + attributes), signed
  with the IdP's private key.
- **Trust:** the SP verifies that signature against the IdP's certificate (from
  the IdP's metadata), then checks audience, validity window, and
  `InResponseTo`.

## The three parties (one app for a runnable demo)

| Role | Endpoints |
|------|-----------|
| **Identity Provider** | `/idp/metadata`, `/idp/sso`, `/idp/login` |
| **Service Provider** | `/sp/metadata`, `/sp/`, `/sp/acs` |
| demo | `/`, `/logout` |

## The flow (SP-initiated)

```
browser        SP                       IdP
  │ GET /sp/login ─▶│                     │
  │◀ 302 /idp/sso?SAMLRequest=… ──────────┤   (AuthnRequest, DEFLATE+base64, HTTP-Redirect)
  │ ───────────────────────────────────────▶│  login, build + SIGN assertion
  │◀ auto-POST form (SAMLResponse) ─────────┤   (HTTP-POST binding)
  │ POST /sp/acs (SAMLResponse) ─▶│          │  verify signature + conditions
  │◀ "signed in as …" ────────────┤          │
```

## A note on the XML signature (why a library)
The assertion is signed with **XML Digital Signature** (enveloped, RSA-SHA256).
We use the vetted **`signxml`** library rather than hand-rolling XML
canonicalization — because doing that yourself is exactly how **XML Signature
Wrapping (XSW)** vulnerabilities arise. The other half of the defense:
`saml.validate_response` reads identity **only from the element `signxml`
confirmed was signed** (`verified.signed_xml`), never from arbitrary XML.

## Run it

```bash
cd 14-saml
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py           # demo user
python app.py            # http://127.0.0.1:5000  (generates the IdP key/cert)
```

Open `http://127.0.0.1:5000/`, click **Sign in with SSO**, log in as
`user@example.com` / `correct-horse-battery-staple`.

Drive it headless (also runs a tamper test):

```bash
COOKIE_SECURE=0 python app.py          # so the session cookie works over HTTP
API_BASE=http://127.0.0.1:5000 python client_example.py
```

Inspect metadata:

```bash
curl -s http://127.0.0.1:5000/idp/metadata
curl -s http://127.0.0.1:5000/sp/metadata
```

## What the SP checks (`saml.validate_response`)
1. **Status** is Success.
2. **Signature** verifies against the IdP certificate (else reject).
3. **`InResponseTo`** (on the Response and the SubjectConfirmationData) equals the
   `AuthnRequest` ID the SP sent — blocks unsolicited/forged assertions.
4. **Recipient** equals this SP's ACS URL.
5. **Conditions**: current time within `NotBefore`/`NotOnOrAfter`.
6. **Audience** equals this SP's entityID — a token minted for another SP is
   refused.
7. **Replay**: an assertion ID is consumed once.

## Threats addressed
| Threat | Defense |
|--------|---------|
| Forged / tampered assertion | XML signature verified against the IdP cert |
| Signature wrapping (XSW) | vetted signer + read only the verified element |
| Assertion minted for another SP | audience restriction check |
| Unsolicited / injected assertion | `InResponseTo` must match a request we made |
| Assertion redirected to a rogue ACS | IdP sends only to the SP's registered ACS |
| Replay | one-time assertion IDs; short validity window |

## Limitations / further hardening
Sign/verify the AuthnRequest too; encrypted assertions (`EncryptedAssertion`);
SP metadata exchange & cert rotation; clock-skew allowance; Single Logout (SLO);
CSRF token on the IdP login form; strict schema validation. Production systems
should use a maintained toolkit (e.g. `python3-saml`, `pysaml2`) rather than a
bespoke SP.
