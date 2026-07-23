"""
app.py — a JSON API authenticated by MUTUAL TLS (client certificates).

There is no Authorization header here. The client proves who it is during the
TLS handshake by presenting a certificate our CA signed; the server is
configured to REQUIRE one. Only after a successful mutual handshake does a
request reach Flask, where we read the client's certificate, derive its
identity (Subject CN + fingerprint), and authorize it.

  transport layer:  TLS handshake  -> proves the client holds a CA-signed cert
  application layer: this app       -> maps the cert to a client, checks
                                       revocation, serves that client's data

    GET /v1/whoami      -> the mTLS identity behind this connection
    GET /v1/resources   -> that client's resources

Run with the stdlib dev server via werkzeug.run_simple so we can require client
certs and pull the peer cert off the socket.
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
    """Werkzeug doesn't surface the client certificate by default. We pull the
    peer cert (DER) off the TLS socket and stash it in the WSGI environ so the
    app can read it."""

    def make_environ(self):
        environ = super().make_environ()
        der = self.connection.getpeercert(binary_form=True)
        if der:
            environ["mtls.peercert_der"] = der
        return environ


def _client_from_request():
    der = request.environ.get("mtls.peercert_der")
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    fp = hashlib.sha256(der).hexdigest()
    return db.authenticate(fp, cn)


def require_mtls(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        client = _client_from_request()
        if client is None:
            # The cert chained to our CA (TLS enforced that) but is unknown,
            # revoked, or its client is inactive.
            auth_log.warning("mTLS authorize failed path=%s", request.path)
            return jsonify(error="forbidden"), 403
        g.client = client
        auth_log.info("mTLS ok client=%s path=%s", client["name"], request.path)
        return view(*args, **kwargs)

    return wrapped


@app.route("/v1/whoami")
@require_mtls
def whoami():
    return jsonify(client_id=g.client["client_id"], name=g.client["name"],
                   authenticated_by="mutual-TLS client certificate")


@app.route("/v1/resources")
@require_mtls
def resources():
    rows = db.get_resources_for_client(g.client["client_id"])
    return jsonify(resources=[dict(r) for r in rows])


def _build_ssl_context():
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_DIR / "server.crt", CERT_DIR / "server.key")
    ctx.load_verify_locations(CERT_DIR / "ca.crt")
    # The heart of mTLS: demand a client certificate our CA signed, or the
    # handshake fails and the request never reaches the app.
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


if __name__ == "__main__":
    if not (CERT_DIR / "ca.crt").exists():
        raise SystemExit("No certs found — run: python seed.py")
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    # Note: with CERT_REQUIRED there is no unauthenticated endpoint — the TLS
    # layer gates every request before Flask sees it.
    run_simple(
        "127.0.0.1", port, app,
        ssl_context=_build_ssl_context(),
        request_handler=PeerCertWSGIRequestHandler,
    )
