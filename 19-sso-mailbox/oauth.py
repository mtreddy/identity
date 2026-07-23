"""
oauth.py — the OAuth2 / PKCE primitives.

Three small, security-critical helpers plus code generation:

  * STATE — an opaque random value the client sends on /authorize and checks on
    the callback. It ties the redirect back to the request the client started,
    defeating CSRF on the redirect.

  * PKCE (Proof Key for Code Exchange, RFC 7636) — the client picks a random
    `code_verifier`, sends only its hash (`code_challenge`) to /authorize, and
    reveals the verifier at /token. An attacker who intercepts the authorization
    CODE still can't redeem it without the verifier. This is what makes it safe
    for public clients (SPAs, mobile, CLIs) that can't keep a secret.

  * AUTH CODE — a short-lived, one-time value bound to (client, user, redirect
    URI, scope, code_challenge). We store only its hash.
"""

import base64
import hashlib
import secrets


def generate_state() -> str:
    return secrets.token_urlsafe(16)


def generate_nonce() -> str:
    """OIDC nonce: a client-generated random value echoed back inside the
    id_token, so the client can detect a replayed/injected token."""
    return secrets.token_urlsafe(16)


def generate_code_verifier() -> str:
    # RFC 7636 allows 43-128 chars; token_urlsafe(64) gives ~86.
    return secrets.token_urlsafe(64)


def code_challenge_s256(verifier: str) -> str:
    """The S256 challenge = base64url(SHA-256(verifier)) with padding stripped."""
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_pkce(verifier: str, challenge: str, method: str = "S256") -> bool:
    """Check a presented verifier against the stored challenge, in constant time."""
    if method == "S256":
        return secrets.compare_digest(code_challenge_s256(verifier), challenge)
    if method == "plain":  # allowed by the spec but discouraged; S256 is preferred
        return secrets.compare_digest(verifier, challenge)
    return False


def generate_auth_code() -> str:
    return secrets.token_urlsafe(32)


def hash_code(code: str) -> str:
    """Auth codes are high-entropy, so a fast hash is fine (same reasoning as
    API keys in mechanism 06). We store the hash so a DB leak can't redeem codes."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
