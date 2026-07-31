"""
app.py — an AI agent calling a model ON BEHALF OF a user (RFC 8693, OBO).

  AUTHORIZATION SERVER (AS)          RESOURCE SERVER / model gateway (RS)
    POST /oauth/token                  GET  /.well-known/oauth-protected-resource
         (client_credentials           GET  /v1/models
          + token-exchange)            POST /v1/models/<model>:invoke   (OBO, SAFE)
    POST /oauth/user-token             POST /vuln/v1/models/<model>:invoke (agent's-own-token foil)
    GET  /.well-known/oauth-authorization-server
    GET  /.well-known/jwks.json

Builds on mechanism 31 (keeping DPoP sender-constraint unchanged). The new idea:
an agent usually acts *for a user*, and it must not be able to do more than that
user may. So instead of calling the model with its OWN broad token, the agent
performs a **token exchange** (RFC 8693): it presents the user's token
(`subject_token`) plus its own client credential, and the AS returns a
**downscoped** access token whose `sub` is the *user* and `act.sub` is the
*agent*. Its authority is the intersection of the user's and the agent's — the
agent can never exceed the user it serves.

The `/vuln` path is the confused deputy: the agent invokes with its **own**
`client_credentials` token, so the gateway authorizes by the *agent's* allow-list
and ignores the user entirely — letting the agent reach a model the user it is
acting for may not use. The `/v1` path fixes this by requiring an OBO token.
Localhost teaching sandbox; not for deployment.
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
    """Both grants authenticate the calling agent (client), then bind the issued
    token to the agent's DPoP key if a proof is present (RFC 9449). They differ in
    the *subject*: client_credentials mints a token for the agent itself; token
    exchange mints one for the USER the agent presents, downscoped to that user."""
    grant = request.form.get("grant_type")
    if grant not in ("client_credentials", config.TE_GRANT):
        return jsonify(error="unsupported_grant_type"), 400
    try:
        client = _authenticate_client(request)
    except clientauth.ClientAuthError:
        return jsonify(error="invalid_client"), 401

    jkt = None
    if request.headers.get("DPoP"):
        try:
            jkt = dpop.verify_proof(request.headers["DPoP"], "POST",
                                    request.base_url, access_token=None)
        except dpop.DPoPError as e:
            return jsonify(error="invalid_dpop_proof", detail=str(e)), 400

    if grant == "client_credentials":
        return _grant_client_credentials(client, jkt)
    return _grant_token_exchange(client, jkt)


def _grant_client_credentials(client, jkt):
    """The agent acts as ITSELF. sub == the agent; no delegation. This token is
    fine for agent-owned work — but on /v1 it is refused, because a model call
    here must be attributed to a user (that refusal is the mechanism)."""
    allowed = client["allowed_scopes"].split()
    requested = request.form.get("scope", "").split()
    if any(s not in allowed for s in requested):
        return jsonify(error="invalid_scope"), 400
    granted = " ".join(requested or allowed)
    audience = request.form.get("resource") or config.GATEWAY_RESOURCE   # RFC 8707
    access_token, ttl = tokens.issue_access_token(
        client["client_id"], client["client_id"], granted, audience, jkt=jkt)
    app.logger.info("client_credentials client=%s aud=%s scope=%s dpop=%s",
                    client["client_id"], audience, granted, bool(jkt))
    return jsonify(_token_response(access_token, ttl, granted, jkt))


def _grant_token_exchange(client, jkt):
    """RFC 8693 on-behalf-of. The agent presents the user's `subject_token`; we
    mint a token whose sub == the user and act.sub == the agent, DOWNSCOPED to the
    intersection of the user's authority and the agent's. The agent can never
    exceed the user it serves — the central agentic authorization control."""
    subject_token = request.form.get("subject_token")
    stype = request.form.get("subject_token_type")
    if not subject_token or stype not in (config.TT_ACCESS, config.TT_JWT):
        return jsonify(error="invalid_request",
                       error_description="missing or unsupported subject_token"), 400
    try:
        user = tokens.verify_user_token(subject_token)
    except Exception:
        # Wrong signature/issuer/expiry — or an *access* token replayed here
        # (wrong aud/token_use). Either way it isn't a valid subject token.
        return jsonify(error="invalid_grant",
                       error_description="subject_token is not a valid user token"), 400

    # RFC 8693 §4.4: the user token names the ONE agent permitted to act for the
    # user. A different agent presenting a user's token is refused — a user's
    # token leaking to another agent does not let that agent impersonate them.
    if user.get("may_act", {}).get("sub") != client["client_id"]:
        return jsonify(error="invalid_client",
                       error_description="client not authorized to act for this subject"), 403

    # Downscope: effective authority = user ∩ agent ∩ requested (least privilege).
    user_scopes = set(user.get("scope", "").split())
    agent_scopes = set(client["allowed_scopes"].split())
    requested = set(request.form.get("scope", "").split())
    effective = user_scopes & agent_scopes
    if requested:
        effective &= requested
    if not effective:
        return jsonify(error="invalid_scope"), 400
    granted = " ".join(sorted(effective))

    # The model set the token may reach is likewise clamped to user ∩ agent, and
    # carried in the token so the gateway enforces the user's limit statelessly.
    eff_models = " ".join(sorted(set(user.get("authorized_models", "").split())
                                 & db.allowed_models(client)))
    audience = request.form.get("resource") or config.GATEWAY_RESOURCE

    access_token, ttl = tokens.issue_access_token(
        user["sub"], client["client_id"], granted, audience, jkt=jkt,
        act={"sub": client["client_id"]}, authorized_models=eff_models)
    app.logger.info("token-exchange sub=%s act=%s aud=%s scope=%s models=[%s] dpop=%s",
                    user["sub"], client["client_id"], audience, granted, eff_models, bool(jkt))
    resp = _token_response(access_token, ttl, granted, jkt)
    resp["issued_token_type"] = config.TT_ACCESS   # RFC 8693 §2.2.1
    return jsonify(resp)


def _token_response(access_token, ttl, scope, jkt) -> dict:
    resp = {"access_token": access_token,
            "token_type": "DPoP" if jkt else "Bearer",
            "expires_in": ttl, "scope": scope}
    if jkt:
        resp["cnf"] = {"jkt": jkt}
    return resp


@app.post("/oauth/user-token")
def user_token():
    """DEV STAND-IN for a user login. In production the `subject_token` is an OIDC
    id/access token the agent obtains when the user signs in (mechanism 10); there
    is no such endpoint. Here it simulates "the user authenticated and delegated
    to this agent", so the demo can drive the exchange. It mints a user token
    carrying the user's own authority and a `may_act` pin to the named agent."""
    user_id = request.form.get("user_id")
    delegatee = request.form.get("delegatee")     # the agent the user delegates to
    row = db.get_user(user_id) if user_id else None
    if row is None or not delegatee:
        return jsonify(error="unknown_user"), 404
    tok, ttl = tokens.issue_user_token(
        row["user_id"], row["allowed_scopes"], row["allowed_models"], delegatee)
    return jsonify(user_token=tok, expires_in=ttl,
                   sub=row["user_id"], may_act=delegatee)


@app.get("/.well-known/oauth-authorization-server")
def as_metadata():          # RFC 8414
    root = request.url_root.rstrip("/")
    return jsonify(
        issuer=config.ISSUER,
        token_endpoint=root + "/oauth/token",
        jwks_uri=root + "/.well-known/jwks.json",
        grant_types_supported=["client_credentials", config.TE_GRANT],
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


def _require_delegation(claims):
    """This gateway serves users, so every call must be attributed to one: the
    token must be an OBO token (RFC 8693) carrying `act`. A plain client_credentials
    token — the agent acting as itself — has no user to answer for and is refused
    here. Returns an error response, or None if the token is a delegated one."""
    act = claims.get("act")
    if not act or "sub" not in act:
        return jsonify(error="delegation_required",
                       error_description="this resource requires an on-behalf-of "
                       "token (RFC 8693); a bare client token is not accepted"), 403
    return None


@app.get("/v1/models")
@require_dpop("models:read")
def list_models():
    if (err := _require_delegation(g.claims)):
        return err
    return jsonify(models=[{"id": m, "description": d}
                           for m, d in gateway.AVAILABLE_MODELS.items()])


@app.post("/v1/models/<model>:invoke")
@require_dpop("model:invoke")
def invoke(model):
    claims = g.claims
    if (err := _require_delegation(claims)):
        return err
    if model not in gateway.AVAILABLE_MODELS:
        return jsonify(error="model_not_found"), 404
    # Authorize against the USER's authority, carried in the token as the
    # user ∩ agent model set the AS computed at exchange. The agent's own broader
    # allow-list does NOT apply here — the whole point of OBO is that it can't.
    if model not in set(claims.get("authorized_models", "").split()):
        return jsonify(error="access_denied",
                       error_description=f"user {claims['sub']} not authorized "
                       f"for {model}"), 403
    body = request.get_json(silent=True) or {}
    result = gateway.invoke_model(model, body.get("prompt", ""))
    result["on_behalf_of"] = claims["sub"]          # the delegation chain, for logs
    result["actor"] = claims["act"]["sub"]
    return jsonify(result)


# ===========================================================================
# /vuln — the same call WITHOUT on-behalf-of delegation (the confused deputy)
# ===========================================================================

@app.post("/vuln/v1/models/<model>:invoke")
@require_dpop("model:invoke")
def vuln_invoke(model):
    # DANGER: this endpoint accepts the agent's OWN client_credentials token and
    # authorizes by the AGENT'S allow-list — it never learns which user the call
    # is for, so it can't hold the call to that user's limits. An agent broadly
    # allow-listed for embed-sim can invoke it while "serving" a user who may not,
    # laundering its own authority into the user's context: the classic confused
    # deputy / over-broad-agent bug. (DPoP is still enforced — the token isn't
    # stolen; the agent itself is over-reaching.) /v1 fixes this by requiring an
    # OBO token whose authority is downscoped to the user.
    claims = g.claims
    if model not in gateway.AVAILABLE_MODELS:
        return jsonify(error="model_not_found"), 404
    client = db.get_client(claims["client_id"])
    if model not in db.allowed_models(client):
        return jsonify(error="access_denied"), 403
    body = request.get_json(silent=True) or {}
    return jsonify(gateway.invoke_model(model, body.get("prompt", "")))


if __name__ == "__main__":
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
