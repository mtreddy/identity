"""
app.py — an AI agent calling a remote model, done two ways.

  AUTHORIZATION SERVER (AS)          RESOURCE SERVER / model gateway (RS)
    POST /oauth/token                  GET  /.well-known/oauth-protected-resource
    GET  /.well-known/                  GET  /v1/models
         oauth-authorization-server     POST /v1/models/<model>:invoke   (SAFE)
    GET  /.well-known/jwks.json         POST /vuln/v1/models/<model>:invoke (foil)

The agent authenticates to the AS (client_secret or, preferred, private_key_jwt)
and gets a SHORT-LIVED, AUDIENCE-BOUND, SCOPED access token; the gateway checks
signature + audience + scope + per-client model allow-list on every call. The
`/vuln` path is the anti-pattern it replaces: a static bearer key with no
audience, no scope, no expiry, and no endpoint verification — one leak = total,
permanent access to every model. Localhost teaching sandbox; not for deployment.
"""

import os
from functools import wraps

from flask import Flask, g, jsonify, request

import clientauth
import config
import crypto_keys
import db
import gateway
import tokens

app = Flask(__name__)


def _bearer(req):
    h = req.headers.get("Authorization", "")
    return h[len("Bearer "):].strip() if h.startswith("Bearer ") else None


# ===========================================================================
# Authorization server
# ===========================================================================

def _presented_client_secret(req):
    """client_secret_basic (HTTP Basic) or client_secret_post (form fields)."""
    auth = req.authorization
    if auth and auth.type == "basic":
        return auth.username, auth.password
    return req.form.get("client_id"), req.form.get("client_secret")


def _authenticate_client(req):
    """Return the authenticated client row, or raise ClientAuthError."""
    if req.form.get("client_assertion_type") == clientauth.ASSERTION_TYPE:
        # The assertion's audience may be this AS's issuer or its live token
        # endpoint — accept either so the check is robust across deployments.
        accepted = [config.ISSUER, request.url_root.rstrip("/") + "/oauth/token"]
        return clientauth.authenticate_private_key_jwt(
            req.form.get("client_assertion", ""), accepted)
    client_id, secret = _presented_client_secret(req)
    if client_id and secret:
        return clientauth.authenticate_client_secret(client_id, secret)
    raise clientauth.ClientAuthError("no client credentials presented")


@app.post("/oauth/token")
def token():
    if request.form.get("grant_type") != "client_credentials":
        return jsonify(error="unsupported_grant_type"), 400
    try:
        client = _authenticate_client(request)
    except clientauth.ClientAuthError:
        return jsonify(error="invalid_client"), 401

    allowed = client["allowed_scopes"].split()
    requested = request.form.get("scope", "").split()
    if any(s not in allowed for s in requested):
        return jsonify(error="invalid_scope"), 400
    granted = " ".join(requested or allowed)

    # RFC 8707: the client names the resource it wants the token for; that
    # becomes the audience. Default to our gateway if the client didn't ask.
    audience = request.form.get("resource") or config.GATEWAY_RESOURCE

    access_token, ttl = tokens.issue_access_token(client["client_id"], granted, audience)
    app.logger.info("token issued client=%s aud=%s scope=%s",
                    client["client_id"], audience, granted)
    return jsonify(access_token=access_token, token_type="Bearer",
                   expires_in=ttl, scope=granted)


@app.get("/.well-known/oauth-authorization-server")
def as_metadata():          # RFC 8414
    root = request.url_root.rstrip("/")
    return jsonify(
        issuer=config.ISSUER,
        token_endpoint=root + "/oauth/token",
        jwks_uri=root + "/.well-known/jwks.json",
        grant_types_supported=["client_credentials"],
        token_endpoint_auth_methods_supported=[
            "client_secret_basic", "client_secret_post", "private_key_jwt"],
        token_endpoint_auth_signing_alg_values_supported=["RS256"],
        scopes_supported=list(config.SCOPES),
    )


@app.get("/.well-known/jwks.json")
def jwks():
    return jsonify(crypto_keys.jwks())


# ===========================================================================
# Resource server (model gateway)
# ===========================================================================

@app.get("/.well-known/oauth-protected-resource")
def protected_resource_metadata():      # RFC 9728
    # Tells the agent which AS to use and, crucially, the canonical `resource`
    # id it must bind its token to. The agent verifies this before trusting us.
    return jsonify(
        resource=config.GATEWAY_RESOURCE,
        authorization_servers=[config.ISSUER],
        scopes_supported=list(config.SCOPES),
        bearer_methods_supported=["header"],
    )


def require_token(required_scope):
    """RS guard: verify the bearer token's signature/issuer/audience/expiry and
    require `required_scope`. On failure, point the agent at our metadata via
    WWW-Authenticate (RFC 9728) so it can discover how to authenticate."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            challenge = ('Bearer resource_metadata="'
                         + request.url_root.rstrip("/")
                         + '/.well-known/oauth-protected-resource"')
            tok = _bearer(request)
            if not tok:
                return jsonify(error="unauthorized"), 401, {"WWW-Authenticate": challenge}
            try:
                claims = tokens.verify_access_token(tok, audience=config.GATEWAY_RESOURCE)
            except Exception:
                # Bad signature, wrong issuer, wrong AUDIENCE, or expired.
                return jsonify(error="invalid_token"), 401, {"WWW-Authenticate": challenge}
            if required_scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient_scope",
                               scope=required_scope), 403, {"WWW-Authenticate": challenge}
            g.claims = claims
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.get("/v1/models")
@require_token("models:read")
def list_models():
    return jsonify(models=[{"id": m, "description": d}
                           for m, d in gateway.AVAILABLE_MODELS.items()])


@app.post("/v1/models/<model>:invoke")
@require_token("model:invoke")
def invoke(model):
    if model not in gateway.AVAILABLE_MODELS:
        return jsonify(error="model_not_found"), 404
    # Per-client authorization: scope says "may invoke a model"; the allow-list
    # says WHICH models this specific agent may invoke.
    client = db.get_client(g.claims["client_id"])
    if model not in db.allowed_models(client):
        return jsonify(error="access_denied",
                       error_description=f"client not authorized for {model}"), 403
    body = request.get_json(silent=True) or {}
    return jsonify(gateway.invoke_model(model, body.get("prompt", "")))


# ===========================================================================
# /vuln — the anti-pattern this mechanism replaces
# ===========================================================================

@app.post("/vuln/v1/models/<model>:invoke")
def vuln_invoke(model):
    # DANGER: a static, long-lived API key as a plain bearer. No audience (the
    # key works at any endpoint that accepts it), no scope, no expiry, and the
    # agent never verified this endpoint. A single leaked key = permanent access
    # to EVERY model. This is exactly what the /v1 path above is designed to fix.
    key = _bearer(request)
    if key is None or db.client_for_api_key(key) is None:
        return jsonify(error="unauthorized"), 401
    body = request.get_json(silent=True) or {}
    return jsonify(gateway.invoke_model(model, body.get("prompt", "")))


if __name__ == "__main__":
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
