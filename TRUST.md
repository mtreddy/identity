# Where trust is anchored (and how to secure each end to end)

Every mechanism in this repo answers "is this caller who they claim to be?" — but
that check is only as good as the thing it ultimately trusts. This document is
the cross-cutting answer to **"what is the root of trust, how was it planted, and
how far does the trust chain reach?"** for each mechanism, and what it takes to
secure each one **end to end**.

It's the trust-anchor companion to [PATTERNS.md](PATTERNS.md) (the design
patterns) and [PROVISIONING.md](PROVISIONING.md) (where identities come from).

> **The short answer.** There is **no single universal root of trust** — no one
> global CA every mechanism chains to. There are about **five classes** of
> anchor. But they share a deeper property: **trust is never created at runtime.
> It is planted once, out-of-band, at *provisioning*, and every runtime
> credential merely chains back to it.** So the CA is one kind of anchor among
> several, and "provisioning ties them to trust" is the accurate framing.

---

## 1. The five classes of trust anchor

| Class | Root of trust | How it's planted (provisioning) | How runtime chains to it | Mechanisms |
|-------|---------------|---------------------------------|--------------------------|------------|
| **A · Symmetric secret** | a secret one or both sides hold | `bootstrap.py`/env → `SECRET_KEY`, `JWT_SECRET`; `seed.py` mints API / provisioning tokens and stores only the **hash** | HMAC signature (cookie, HS256 JWT) or hash-lookup (API key) | 01–05 (`SECRET_KEY`), 06/07/08 (API key, `JWT_SECRET`), 18/26 (provisioning tokens) |
| **B · Asymmetric key** | a **private** key held by one party; the **public** key trusted by verifiers | provider/AS generates its signing key on first run; each client's **public key is registered** at provisioning | verifier checks a signature against the public key (via JWKS / `kid`) | 10/19 (OIDC RS256), 30–32 (AS key + agents' `private_key_jwt` public keys), 13/31 (DPoP) |
| **C · CA / PKI** | a **Certificate Authority** key (the classic hierarchical root) | `seed.py` runs `pki.create_ca()` → `certs/ca.crt`, issues per-client certs, registers fingerprints | TLS handshake verifies the cert chains to the CA; the app then checks a fingerprint / ID **policy** | 11 (mTLS), 12 (cert-bound), 15 (SPIFFE **trust bundle** = CA + JWKS), 14 (SAML IdP cert) |
| **D · Out-of-band possession** | control of a channel, or a shared enrollment secret | the enrollment ceremony itself: email link (25), QR / `otpauth` (16), passkey registration (17) | prove control: click the link, produce the current code, sign the challenge | 01 (password), 25 (email), 16 (TOTP), 17 (WebAuthn, trust-on-first-use) |
| **E · Delegated / derived** | *no new root* — it composes A–D | nothing new is provisioned; it references existing anchors | the token chains to (AS signing key) ∩ (the user's login) ∩ (client registration) | 09/10/19/24 (OAuth), 32 (OBO: user token ∩ agent key) |

Two anchors are usually stacked. mTLS (11) has a **cryptographic** root (the CA,
who *may* connect) *and* an **authorization** root (the DB fingerprint allow-list,
*which* cert we actually registered). A cert we didn't issue, or one we revoked,
is rejected even though it chains to the CA. Cert-bound tokens (12) add a third:
the token's own signing secret. Layered anchors are the norm, not the exception.

---

## 2. The unifying insight: trust bottoms out at provisioning

Trace any mechanism's trust backward and it ends at an **out-of-band act during
provisioning**, never at anything the runtime protocol itself did:

- A **JWT** is trusted because it's signed by a key that was *generated and
  registered* at seed time.
- An **mTLS cert** is trusted because it chains to a CA whose key someone
  *created and protected*.
- A **passkey** is trusted because the server *stored its public key on first
  registration* (trust-on-first-use).
- A **session cookie** is trusted because it's signed with a `SECRET_KEY` a
  human / secret-manager *provisioned*.

This is why the **bootstrap gap** — *"how do you trust the very first key
exchange?"* — is the residual risk in every system. The regress terminates only
at something human or physical: a CA key an operator authorized in an HSM, an IdP
admin, a developer running `seed.py`, a user's mailbox. It is turtles all the way
down until one **out-of-band, human-rooted** turtle.

The nearest thing to a single "common root like a CA" is what **SPIFFE (15) makes
explicit**: one **trust bundle** (CA PEM + JWKS) that every workload in a trust
domain shares, with *federation = exchanging bundles across domains*. That's the
model the rest of the repo approximates with per-mechanism anchors.

---

## 3. Securing each mechanism end to end

The same recipe specializes per anchor class:

> **protect the root → prefer asymmetric → rotate → bind to transport + sender →
> constrain → close the bootstrap gap → detect.**

| Mechanism(s) | The anchor to protect | End-to-end hardening (beyond what the demo shows) |
|--------------|-----------------------|---------------------------------------------------|
| **01–05** login | `SECRET_KEY` (forges *any* session) | secret manager, not env/source; rotate with a key-id + grace window; already `HttpOnly`/`Secure`/`SameSite` + server-side revocable sessions (05) |
| **06** API keys | the key + its hash-at-rest | scope keys; expiry + rotation; per-key rate-limit; TLS mandatory; ship `last_used_at` / auth logs to alerting |
| **07/08** JWT | `JWT_SECRET` — with **HS256 a verifier can also mint** | move to **RS256/JWKS** so resource servers hold no minting secret; short TTL + `jti` deny-list (08) for revocation; rotate `kid`s |
| **10/19** OIDC | the provider's RSA private key | HSM/KMS for the key; JWKS **rotation** (multiple `kid`); `nonce` + `aud` (done); cache-control on JWKS; `at_hash` binding |
| **11/12** mTLS / cert-bound | the **CA key** | CA key in an HSM; **short-lived certs + automated issuance** (SPIRE / mesh); real revocation (CRL/OCSP), not just a fingerprint flag; EKU / name constraints on the CA |
| **13/31** DPoP | the client's private key | keep it in an enclave/memory, **never in a prompt**; shared `jti` store (TTL = proof age); server-issued `DPoP-Nonce`; the token still chains to the AS key, so harden that too |
| **14** SAML | the IdP signing cert (in metadata) | sign the `AuthnRequest` too; encrypted assertions; **metadata / cert rotation**; use a maintained toolkit — XML-signature-wrapping is a footgun |
| **15** SPIFFE | the **trust bundle** (CA + JWKS) | real **SPIRE** with node/workload **attestation** (a workload can obtain only its *own* SVID); short-TTL SVID rotation; federate bundles across trust domains |
| **16/17** 2FA | shared secret (16) / device key (17) | 16: encrypt the secret at rest, reject step-reuse, add backup codes. 17: require the **user-verification** flag; enterprise **attestation** to root the passkey in a manufacturer CA; gate registration behind an authenticated session |
| **18/26** provisioning | the provisioning / registration token | store hashed (done); scope + rate-limit; rotate; 26: **software statements** (signed metadata) to root client identity; strict `redirect_uri` + scope clamp (done) |
| **25** signup | control of the email channel | treat the link as a bearer secret in transit and logs; short TTL + single-use (done); step-up for high-value actions — email control is a *moment*, not durable proof |
| **27** API authz | *n/a — no new anchor* | the point: authorization chains to identity but adds per-object / field / function checks; centralize the policy; return `404` not `403`; enforce a response schema at the edge |
| **30–32** agent→model | the AS signing key **+** each agent's registered public key | **pin the model endpoint** (resource-id via PRM — done; cryptographic model provenance / TEE attestation is `33`); `private_key_jwt` (no shared secret — done); DPoP sender-constraint (31); OBO downscoping (32); per-agent budget/rate as an authorization decision |

---

## 4. The through-line

A system is only as trustworthy as:

1. **How well its root is protected** — HSM / KMS / enclave, never in source or
   git (the repo gitignores every generated key, cert, and DB for exactly this
   reason).
2. **Whether the root is asymmetric** — so a party that can *verify* cannot also
   *mint* (the `07 → 10` move, and the whole `30–32` design).
3. **How the runtime binds credentials** — to a key and to the transport
   (sender-constraint: mTLS 11/12, DPoP 13/31), so a leaked bearer string is
   inert.
4. **How rigorously provisioning is attested** — because that is where trust is
   actually *born*. **Attestation** (SPIRE node/workload, WebAuthn authenticator,
   TEE for models) is the frontier that closes the bootstrap gap the rest of the
   stack otherwise takes on faith.

The catalog trends, mechanism by mechanism, from **trust asserted** (a shared
secret, believed because you hold it) toward **trust proven and attested** (an
asymmetric, sender-bound credential whose very issuance can be cryptographically
vouched for) — the same arc [PATTERNS.md](PATTERNS.md) traces, seen from the root
of trust rather than the credential.
