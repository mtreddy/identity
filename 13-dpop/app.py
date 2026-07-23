"""
app.py — DPoP-bound access tokens (RFC 9449).

Sender-constrained tokens WITHOUT mTLS. The client holds its own keypair and
signs a fresh DPoP proof on every request; the access token is bound to that
key's thumbprint (cnf.jkt). A stolen token can't be used without the private
key — the same guarantee as mechanism 12, but purely at the application layer
(plain HTTP, no client certificates).

  POST /v1/token       X-API-Key + DPoP proof  -> DPoP-bound access token
  GET  /v1/whoami      Authorization: DPoP <t> + DPoP proof (ath) -> identity
  GET  /v1/resources   Authorization: DPoP <t> + DPoP proof (ath) -> resources

Runs over plain HTTP so the DPoP mechanics are easy to watch; in production this
still belongs behind TLS to protect the token and proofs in transit.
"""

import functools
import logging
import os

from flask import Flask, g, jsonify, request

import db
import dpop
import tokens

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "auth.log")),
        logging.StreamHandler(),
    ],
)
auth_log = logging.getLogger("auth")


@app.route("/v1/token", methods=["POST"])
def token():
    # 1) Authenticate the client with its API key (kept in X-API-Key so the
    #    Authorization header stays free for the DPoP scheme elsewhere).
    api_key = request.headers.get("X-API-Key", "").strip()
    client = db.authenticate(api_key) if api_key else None
    if client is None:
        auth_log.warning("token: bad api key ip=%s", request.remote_addr)
        return jsonify(error="invalid_client"), 403

    # 2) Require a DPoP proof for this POST and learn the client's key thumbprint.
    try:
        jkt = dpop.verify_proof(
            request.headers.get("DPoP", ""), "POST", request.base_url, access_token=None
        )
    except dpop.DPoPError as e:
        auth_log.warning("token: bad DPoP proof (%s)", e)
        return jsonify(error="invalid_dpop_proof", detail=str(e)), 400

    scope = " ".join(db.get_client_scopes(client["client_id"]))
    access_token, ttl = tokens.issue_access_token(
        client["client_id"], client["name"], scope, jkt
    )
    auth_log.info("token issued (DPoP-bound) client=%s jkt=%s…", client["name"], jkt[:12])
    return jsonify(
        access_token=access_token,
        token_type="DPoP",          # RFC 9449: not "Bearer"
        expires_in=ttl,
        scope=scope,
        cnf={"jkt": jkt},
    )


def require_dpop(scope=None):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            # The access token is presented with the DPoP auth scheme.
            header = request.headers.get("Authorization", "")
            if not header.startswith("DPoP "):
                return jsonify(error="unauthorized"), 401
            access_token = header[len("DPoP "):].strip()

            try:
                claims = tokens.verify_access_token(access_token)
            except Exception:
                return jsonify(error="invalid_token"), 401

            # Verify the per-request proof, tying it to THIS method+URL and to
            # THIS access token (ath), and get the proof key's thumbprint.
            try:
                jkt = dpop.verify_proof(
                    request.headers.get("DPoP", ""), request.method,
                    request.base_url, access_token=access_token,
                )
            except dpop.DPoPError as e:
                auth_log.warning("resource: bad DPoP proof (%s) path=%s", e, request.path)
                return jsonify(error="invalid_dpop_proof", detail=str(e)), 401

            # THE BINDING CHECK: the proof's key must be the one the token is
            # bound to. A stolen token signed-over by a different key fails here.
            if claims.get("cnf", {}).get("jkt") != jkt:
                auth_log.warning("resource: jkt MISMATCH sub=%s", claims.get("sub"))
                return jsonify(error="invalid_token",
                               detail="access token not bound to this DPoP key"), 401

            if scope is not None and scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient_scope", required=scope), 403

            g.claims = claims
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.route("/v1/whoami")
@require_dpop()
def whoami():
    return jsonify(client_id=int(g.claims["sub"]), name=g.claims.get("name"),
                   scope=g.claims.get("scope", ""),
                   bound_to=g.claims["cnf"]["jkt"])


@app.route("/v1/resources")
@require_dpop(scope="resources:read")
def resources():
    rows = db.get_resources_for_client(int(g.claims["sub"]))
    return jsonify(resources=[dict(r) for r in rows])


if __name__ == "__main__":
    tokens._secret()  # fail fast if JWT_SECRET is missing
    db.init_schema()
    debug = os.environ.get("FLASK_DEBUG") == "1"
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug)
