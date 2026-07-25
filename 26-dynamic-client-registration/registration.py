"""
registration.py — the Dynamic Client Registration primitives (RFC 7591 / 7592).

Mechanism 09 hard-codes the one OAuth client in seed.py. Real deployments let
clients register themselves at a protocol endpoint. That convenience is also an
attack surface, so the security lives in three places, all here:

  * IDENTIFIERS & SECRETS — client_id (public), an optional client_secret for
    confidential clients, and a per-client *registration access token* (RAT)
    that authorizes later read/update/delete of THAT client only (RFC 7592).
    Secrets and the RAT are high-entropy, so we store only their SHA-256 hash
    (same reasoning as API keys in 06); the raw values are shown exactly once.

  * METADATA VALIDATION — the redirect_uri allow-list is the single most
    important control in the whole OAuth system (it's where codes/tokens get
    sent). validate_metadata() rejects non-absolute URIs, fragments, and plain
    http to anything but loopback, and clamps requested scopes to what the
    server actually supports. A client cannot register itself more privilege
    than the server offers.

  * AUTH METHOD — "none" means a public client that must use PKCE and gets no
    secret; "client_secret_basic"/"client_secret_post" mint a secret.
"""

import hashlib
import secrets
import urllib.parse

SUPPORTED_SCOPES = {"profile", "resources:read", "resources:write"}
SUPPORTED_GRANT_TYPES = {"authorization_code"}
SUPPORTED_AUTH_METHODS = {"none", "client_secret_basic", "client_secret_post"}


# --- identifier / secret generation -----------------------------------------

def new_client_id() -> str:
    return "c_" + secrets.token_urlsafe(16)


def new_client_secret() -> str:
    return secrets.token_urlsafe(32)


def new_registration_access_token() -> str:
    return "rat_" + secrets.token_urlsafe(32)


def hash_secret(value: str) -> str:
    """High-entropy secrets/tokens: a fast hash is correct. We never store the
    clear value, so a DB leak can't authenticate as the client."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_secret(presented: str, stored_hash: str) -> bool:
    if not presented or not stored_hash:
        return False
    return secrets.compare_digest(hash_secret(presented), stored_hash)


# --- metadata validation ----------------------------------------------------

def _valid_redirect_uri(uri: str) -> bool:
    """A redirect URI must be absolute, carry no fragment, and — because an
    authorization code will be delivered to it — use https, with plain http
    tolerated only for loopback (the local-dev exception the specs carve out)."""
    try:
        p = urllib.parse.urlparse(uri)
    except ValueError:
        return False
    if not p.scheme or not p.netloc or p.fragment:
        return False
    if p.scheme == "https":
        return True
    if p.scheme == "http":
        host = p.hostname or ""
        return host in ("127.0.0.1", "localhost", "::1")
    return False


def validate_metadata(body: dict) -> tuple[dict, str | None]:
    """Validate + normalize a registration request. Returns (metadata, error).
    On error, `metadata` is {} and the caller returns an RFC 7591 error JSON."""
    if not isinstance(body, dict):
        return {}, "invalid_client_metadata"

    uris = body.get("redirect_uris")
    if not isinstance(uris, list) or not uris:
        return {}, "invalid_redirect_uri"       # redirect_uris is REQUIRED
    if not all(isinstance(u, str) and _valid_redirect_uri(u) for u in uris):
        return {}, "invalid_redirect_uri"

    auth_method = body.get("token_endpoint_auth_method", "none")
    if auth_method not in SUPPORTED_AUTH_METHODS:
        return {}, "invalid_client_metadata"

    grant_types = body.get("grant_types") or ["authorization_code"]
    if any(g not in SUPPORTED_GRANT_TYPES for g in grant_types):
        return {}, "invalid_client_metadata"

    response_types = body.get("response_types") or ["code"]
    if any(r != "code" for r in response_types):
        return {}, "invalid_client_metadata"

    # A client may ASK for scopes; it only ever GETS the supported subset.
    requested = (body.get("scope") or "").split()
    granted = [s for s in requested if s in SUPPORTED_SCOPES]
    if not granted:
        granted = ["profile", "resources:read"]   # sensible default

    name = body.get("client_name") or "Dynamically Registered Client"
    if not isinstance(name, str) or len(name) > 200:
        return {}, "invalid_client_metadata"

    return {
        "client_name": name,
        "redirect_uris": uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": auth_method,
        "scope": " ".join(granted),
        "is_public": 1 if auth_method == "none" else 0,
    }, None
