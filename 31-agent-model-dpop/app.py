"""
app.py — an AI agent calling a remote model with a SENDER-CONSTRAINED token.

  AUTHORIZATION SERVER (AS)          RESOURCE SERVER / model gateway (RS)
    POST /oauth/token                  GET  /.well-known/oauth-protected-resource
    GET  /.well-known/                  GET  /v1/models
         oauth-authorization-server     POST /v1/models/<model>:invoke   (DPoP, SAFE)
    GET  /.well-known/jwks.json         POST /vuln/v1/models/<model>:invoke (bearer foil)

Builds on mechanism 30. The agent still authenticates with private_key_jwt /
client_secret and gets an audience-bound, scoped token — but now it also proves
possession of a **DPoP key** (RFC 9449): it sends a DPoP proof when requesting
the token, so the token carries `cnf.jkt`, and it signs a fresh proof on every
call. The gateway checks that proof against `cnf.jkt`, so a **stolen token is
useless** without the agent's private key.

The `/vuln` path is the bearer version of the same call (mechanism 30's safe
endpoint): a copied token there is replayable by anyone. That is exactly the
replay risk DPoP removes. Localhost teaching sandbox; not for deployment.
"""

import os
from functools import wraps

from flask import Flask, g, jsonify, request

import clientauth
import config
import crypto_keys
import db
import dpop
import gateway
import tokens

app = Flask(__name__)


def _bearer(req):
    h = req.headers.get("Authorization", "")
    return h[len("Bearer "):].strip() if h.startswith("Bearer ") else None


def _dpop_token(req):
    """The access token presented with the DPoP auth scheme (not Bearer)."""
    h = req.headers.get("Authorization", "")
    return h[len("DPoP "):].strip() if h.startswith("DPoP ") else None


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

    # RFC 9449: if the agent presents a DPoP proof at the token endpoint, bind
    # the issued token to that key's thumbprint (cnf.jkt) and mark it "DPoP".
    # Without a proof we fall back to a plain bearer token — the /vuln foil.
    jkt = None
    if request.headers.get("DPoP"):
        try:
            jkt = dpop.verify_proof(request.headers["DPoP"], "POST",
                                    request.base_url, access_token=None)
        except dpop.DPoPError as e:
            return jsonify(error="invalid_dpop_proof", detail=str(e)), 400

    access_token, ttl = tokens.issue_access_token(
        client["client_id"], granted, audience, jkt=jkt)
    app.logger.info("token issued client=%s aud=%s scope=%s dpop=%s",
                    client["client_id"], audience, granted, bool(jkt))
    resp = {"access_token": access_token,
            "token_type": "DPoP" if jkt else "Bearer",
            "expires_in": ttl, "scope": granted}
    if jkt:
        resp["cnf"] = {"jkt": jkt}
    return jsonify(resp)


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
    # Tells the agent which AS to use, the canonical `resource` id it must bind
    # its token to, and that this RS requires DPoP-bound tokens (ES256 proofs).
    return jsonify(
        resource=config.GATEWAY_RESOURCE,
        authorization_servers=[config.ISSUER],
        scopes_supported=list(config.SCOPES),
        bearer_methods_supported=["header"],
        dpop_signing_alg_values_supported=["ES256"],
    )


def require_dpop(required_scope):
    """RS guard (RFC 9449): the access token is presented with the `DPoP` auth
    scheme AND a fresh DPoP proof. We verify the token (sig/iss/aud/exp/scope),
    verify the proof (sig/htm/htu/iat/jti/ath), then require the proof's key to
    match the token's `cnf.jkt` — so holding the token isn't enough; you must
    hold its bound private key. A stolen token alone is inert."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            challenge = ('DPoP resource_metadata="'
                         + request.url_root.rstrip("/")
                         + '/.well-known/oauth-protected-resource"')
            def deny(err, code):
                return jsonify(error=err), code, {"WWW-Authenticate": challenge}

            tok = _dpop_token(request)
            if not tok:
                return deny("unauthorized", 401)
            try:
                claims = tokens.verify_access_token(tok, audience=config.GATEWAY_RESOURCE)
            except Exception:
                return deny("invalid_token", 401)   # bad sig/iss/AUDIENCE/expiry
            if required_scope not in claims.get("scope", "").split():
                return deny("insufficient_scope", 403)
            # Proof-of-possession: the DPoP proof must be valid for THIS request
            # (htm/htu/ath) and signed by the token's bound key.
            try:
                jkt = dpop.verify_proof(request.headers.get("DPoP", ""),
                                        request.method, request.base_url,
                                        access_token=tok)
            except dpop.DPoPError:
                return deny("invalid_dpop_proof", 401)
            if claims.get("cnf", {}).get("jkt") != jkt:
                return deny("invalid_token", 401)    # token not bound to this key
            g.claims = claims
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.get("/v1/models")
@require_dpop("models:read")
def list_models():
    return jsonify(models=[{"id": m, "description": d}
                           for m, d in gateway.AVAILABLE_MODELS.items()])


@app.post("/v1/models/<model>:invoke")
@require_dpop("model:invoke")
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
# /vuln — the same call WITHOUT proof-of-possession
# ===========================================================================

@app.post("/vuln/v1/models/<model>:invoke")
def vuln_invoke(model):
    # DANGER: accepts the access token as a plain BEARER — it verifies the JWT
    # but does NOT require a DPoP proof, so it never checks that the caller holds
    # the bound key. Whoever holds the token STRING can call this; a leaked or
    # logged token is replayable by anyone. The /v1 endpoint closes exactly this
    # by requiring the matching DPoP proof (mechanism 30's token, made unstealable).
    tok = _bearer(request)
    if not tok:
        return jsonify(error="unauthorized"), 401
    try:
        claims = tokens.verify_access_token(tok, audience=config.GATEWAY_RESOURCE)
    except Exception:
        return jsonify(error="invalid_token"), 401
    if "model:invoke" not in claims.get("scope", "").split():
        return jsonify(error="insufficient_scope"), 403
    if model not in gateway.AVAILABLE_MODELS:
        return jsonify(error="model_not_found"), 404
    body = request.get_json(silent=True) or {}
    return jsonify(gateway.invoke_model(model, body.get("prompt", "")))


if __name__ == "__main__":
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
