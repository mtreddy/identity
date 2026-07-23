"""
app.py — a SPIFFE-authenticated API server workload.

It accepts a caller in two SPIFFE ways, and authorizes by the caller's SPIFFE
ID (never a hostname or CN):

  * X.509-SVID (mTLS): the caller presents a client cert whose URI SAN is its
    SPIFFE ID, chaining to the trust-bundle CA. Routes under /x509/*.
  * JWT-SVID: the caller presents `Authorization: Bearer <jwt-svid>` whose `aud`
    is THIS server's SPIFFE ID, verified against the bundle JWKS. Routes /jwt/*.

The server itself has an X.509-SVID (server.pem) so callers can verify IT by
its SPIFFE ID. mTLS is CERT_OPTIONAL so the JWT-SVID routes work without a
client certificate (that's the point of JWT-SVIDs).

    GET /x509/whoami     mTLS SVID   -> caller SPIFFE ID
    GET /x509/resources  mTLS SVID   -> caller's resources
    GET /jwt/whoami      JWT-SVID    -> caller SPIFFE ID
"""

import functools
import hashlib
import json
import logging
import os
from pathlib import Path

import jwt as pyjwt
from cryptography import x509
from flask import Flask, g, jsonify, request
from werkzeug.serving import WSGIRequestHandler, run_simple

import spiffe

TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "example.org")
SVID_DIR = Path(os.environ.get("SVID_DIR", Path(__file__).parent / "svids"))


def sid(path):
    return f"spiffe://{TRUST_DOMAIN}/{path}"


SERVER_ID = sid("workload/api-server")

# Authorization policy + data, keyed by SPIFFE ID. `rogue` is intentionally
# absent: it has a valid SVID but no grant.
RESOURCES = {
    sid("workload/billing"): [
        {"title": "invoice template", "body": "Net-30 terms, remit to Acme Inc."},
        {"title": "tax rate", "body": "8.75%"},
    ],
    sid("workload/analytics"): [
        {"title": "dashboard token", "body": "grafana-ro-abc123"},
    ],
}
ALLOWED = set(RESOURCES)

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s",
                    handlers=[logging.FileHandler(SVID_DIR.parent / "auth.log"),
                              logging.StreamHandler()])
auth_log = logging.getLogger("auth")

_JWKS = None


def _jwks():
    global _JWKS
    if _JWKS is None:
        _JWKS = json.loads((SVID_DIR / "bundle_jwks.json").read_text())
    return _JWKS


class PeerCertWSGIRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        der = self.connection.getpeercert(binary_form=True)
        if der:
            environ["mtls.peercert_der"] = der
        return environ


def _authorize(caller_id, path):
    if spiffe.trust_domain(caller_id) != TRUST_DOMAIN:
        return "wrong trust domain"
    if caller_id not in ALLOWED:
        return "not authorized by policy"
    return None


# --- X.509-SVID (mTLS) ------------------------------------------------------

def require_x509_svid(scope_view):
    @functools.wraps(scope_view)
    def wrapped(*a, **k):
        der = request.environ.get("mtls.peercert_der")
        if not der:
            return jsonify(error="client_svid_required"), 401
        caller = spiffe.spiffe_id_from_cert(x509.load_der_x509_certificate(der))
        if not caller:
            return jsonify(error="no_spiffe_id_in_cert"), 401
        denied = _authorize(caller, request.path)
        if denied:
            auth_log.warning("x509 deny %s (%s)", caller, denied)
            return jsonify(error="forbidden", detail=denied, caller=caller), 403
        g.caller = caller
        auth_log.info("x509 ok %s -> %s", caller, request.path)
        return scope_view(*a, **k)
    return wrapped


@app.route("/x509/whoami")
@require_x509_svid
def x509_whoami():
    return jsonify(caller=g.caller, authenticated_by="X.509-SVID (mTLS)")


@app.route("/x509/resources")
@require_x509_svid
def x509_resources():
    return jsonify(resources=RESOURCES[g.caller])


# --- JWT-SVID ---------------------------------------------------------------

@app.route("/jwt/whoami")
def jwt_whoami():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify(error="jwt_svid_required"), 401
    token = header[7:].strip()
    try:
        kid = pyjwt.get_unverified_header(token)["kid"]
        jwk = next(k for k in _jwks()["keys"] if k["kid"] == kid)
        key = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        # audience MUST be this server — a JWT-SVID minted for another service
        # can't be replayed here.
        caller = spiffe.verify_jwt_svid(token, key, audience=SERVER_ID)
    except Exception as e:
        auth_log.warning("jwt-svid invalid (%s)", e)
        return jsonify(error="invalid_jwt_svid", detail=str(e)), 401
    denied = _authorize(caller, request.path)
    if denied:
        return jsonify(error="forbidden", detail=denied, caller=caller), 403
    auth_log.info("jwt-svid ok %s -> %s", caller, request.path)
    return jsonify(caller=caller, authenticated_by="JWT-SVID", audience=SERVER_ID)


def _ssl_context():
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SVID_DIR / "server.pem", SVID_DIR / "server_key.pem")
    ctx.load_verify_locations(SVID_DIR / "bundle_ca.pem")
    # OPTIONAL: present-a-cert enables X.509-SVID routes; JWT-SVID routes work
    # without one. A cert that doesn't chain to the bundle CA fails the handshake.
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


if __name__ == "__main__":
    if not (SVID_DIR / "server.pem").exists():
        raise SystemExit("No SVIDs — run: python seed.py")
    port = int(os.environ.get("PORT", "5000"))
    run_simple("127.0.0.1", port, app, ssl_context=_ssl_context(),
               request_handler=PeerCertWSGIRequestHandler)
