"""
app.py — certificate-bound access tokens (RFC 8705), combining mTLS (11) with
JWT (07).

The whole server runs under mutual TLS (client cert REQUIRED), so a client
certificate is present on every connection. Two phases:

  1. POST /v1/token        The client authenticates with its cert (mTLS). We
                           issue a JWT whose `cnf.x5t#S256` claim is bound to
                           THAT certificate's thumbprint.
  2. GET  /v1/resources    The client presents the token AND (over mTLS) its
                           cert. We verify the token, then check the presented
                           cert's thumbprint equals the token's `cnf` — proving
                           the caller is the client the token was issued to.

Net effect: the access token is sender-constrained. A stolen token replayed by
a different client (a different cert) is rejected.

    POST /v1/token       cert -> certificate-bound access token
    GET  /v1/whoami      token + matching cert -> identity
    GET  /v1/resources   token + matching cert -> that client's resources
"""

import functools
import hashlib
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Flask, g, jsonify, request
from werkzeug.serving import WSGIRequestHandler, run_simple

import db
import pki
import tokens

CERT_DIR = Path(os.environ.get("CERT_DIR", Path(__file__).parent / "certs"))

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


class PeerCertWSGIRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        der = self.connection.getpeercert(binary_form=True)
        if der:
            environ["mtls.peercert_der"] = der
        return environ


def _peer_cert():
    """Return (der, cn, fingerprint_hex, x5t) for the mTLS client cert, or None.
    The cert is guaranteed present (CERT_REQUIRED) once a request reaches us."""
    der = request.environ.get("mtls.peercert_der")
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return der, cn, hashlib.sha256(der).hexdigest(), pki.x5t_s256_from_der(der)


# --- token endpoint: mTLS client auth -> cert-bound token -------------------

@app.route("/v1/token", methods=["POST"])
def token():
    peer = _peer_cert()
    if peer is None:
        return jsonify(error="client_certificate_required"), 401
    _der, cn, fp, x5t = peer

    client = db.authenticate(fp, cn)   # known + not revoked + CN matches
    if client is None:
        auth_log.warning("token: unknown/revoked cert cn=%s", cn)
        return jsonify(error="invalid_client"), 403

    scope = " ".join(db.get_client_scopes(client["client_id"]))
    access_token, ttl = tokens.issue_access_token(
        client["client_id"], client["name"], scope, x5t
    )
    auth_log.info("token issued (cert-bound) client=%s x5t=%s…", client["name"], x5t[:12])
    return jsonify(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ttl,
        scope=scope,
        # Informational: the thumbprint this token is bound to.
        cnf={"x5t#S256": x5t},
    )


# --- resource access: token MUST match the presented cert -------------------

def require_bound_token(scope=None):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            peer = _peer_cert()
            if peer is None:
                return jsonify(error="client_certificate_required"), 401
            _der, cn, fp, presented_x5t = peer

            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="unauthorized"), 401
            try:
                claims = tokens.verify_access_token(header[7:].strip())
            except Exception:
                return jsonify(error="invalid_token"), 401

            # THE BINDING CHECK: the token's cnf thumbprint must equal the
            # thumbprint of the certificate presented on THIS connection.
            bound = claims.get("cnf", {}).get("x5t#S256")
            if bound != presented_x5t:
                auth_log.warning(
                    "token/cert MISMATCH sub=%s bound=%s… presented=%s…",
                    claims.get("sub"), str(bound)[:12], presented_x5t[:12])
                return jsonify(error="invalid_token",
                               detail="token not bound to presented certificate"), 401

            # Defense in depth: the cert must still be valid (catches revocation,
            # since the cert is presented on every call).
            if db.authenticate(fp, cn) is None:
                return jsonify(error="forbidden"), 403

            if scope is not None and scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient_scope", required=scope), 403

            g.claims = claims
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.route("/v1/whoami")
@require_bound_token()
def whoami():
    return jsonify(client_id=int(g.claims["sub"]), name=g.claims.get("name"),
                   scope=g.claims.get("scope", ""),
                   bound_to=g.claims["cnf"]["x5t#S256"])


@app.route("/v1/resources")
@require_bound_token(scope="resources:read")
def resources():
    rows = db.get_resources_for_client(int(g.claims["sub"]))
    return jsonify(resources=[dict(r) for r in rows])


def _build_ssl_context():
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_DIR / "server.crt", CERT_DIR / "server.key")
    ctx.load_verify_locations(CERT_DIR / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED   # mutual TLS: client cert on every call
    return ctx


if __name__ == "__main__":
    if not (CERT_DIR / "ca.crt").exists():
        raise SystemExit("No certs found — run: python seed.py")
    tokens._secret()  # fail fast if JWT_SECRET is missing
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    run_simple(
        "127.0.0.1", port, app,
        ssl_context=_build_ssl_context(),
        request_handler=PeerCertWSGIRequestHandler,
    )
