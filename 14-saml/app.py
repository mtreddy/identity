"""
app.py — SAML 2.0 Web Browser SSO (SP-initiated).

For a self-contained demo one process plays all three roles (kept in labelled
sections); in the real world they're separate organisations.

  (IdP) /idp/metadata  /idp/sso  /idp/login     authenticates the user, signs
                                                 and returns an assertion
  (SP)  /sp/metadata   /sp/       /sp/acs        starts SSO, consumes assertions
  demo  /              /logout

Flow (SP-initiated, AuthnRequest via HTTP-Redirect, Response via HTTP-POST):

  browser        SP                     IdP
    │  GET /sp/ ─▶│                       │
    │◀─ 302 to /idp/sso?SAMLRequest=… ────┤ (AuthnRequest, deflated+b64)
    │  ───────────────────────────────────▶│  login + build signed assertion
    │◀─ auto-POST form: SAMLResponse ──────┤
    │  POST /sp/acs (SAMLResponse) ─▶│      │  validate signature + conditions
    │◀─ "signed in as …" ────────────┤      │
"""

import functools
import os

from flask import (
    Flask, redirect, render_template, request, session, url_for,
)

import db
import idp_keys
import saml

app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY is not set (needed for the session cookie).")
app.secret_key = _secret
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1")

# An assertion ID may be consumed once (replay protection). In-memory for the
# demo; a shared store in production.
SEEN_ASSERTIONS: set[str] = set()


def base_url():
    return request.host_url.rstrip("/")


def idp_entity():   return base_url() + "/idp"
def idp_sso_url():  return base_url() + "/idp/sso"
def sp_entity():    return base_url() + "/sp"
def sp_acs_url():   return base_url() + "/sp/acs"


# ===========================================================================
# (IdP) Identity Provider
# ===========================================================================

@app.route("/idp/metadata")
def idp_metadata():
    xml = f"""<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{idp_entity()}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <X509Data><X509Certificate>{idp_keys.cert_b64_der()}</X509Certificate></X509Data>
    </KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="{idp_sso_url()}"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""
    return app.response_class(xml, mimetype="application/xml")


def _issue_response(saml_request_b64, relay_state):
    """Parse the AuthnRequest, and (assuming the user is authenticated) build
    the auto-POST page carrying a signed Response back to the SP's ACS."""
    req = saml.read_authn_request(saml.inflate_b64(saml_request_b64))
    # Only issue to a registered SP, and always send to the REGISTERED ACS
    # (never an ACS URL taken from the request) — avoids assertion redirection.
    if req["issuer"] != sp_entity():
        return render_template("error.html", message="Unknown SP."), 400

    user = db.get_user_by_email(session["idp_email"])
    xml = saml.build_signed_response(
        idp_entity_id=idp_entity(), sp_entity_id=sp_entity(), acs_url=sp_acs_url(),
        in_response_to=req["id"],
        user={"email": user["email"], "name": user["name"] or ""},
        key_pem=idp_keys.PRIVATE_PEM, cert_pem=idp_keys.CERT_PEM,
    )
    return render_template("idp_post.html", acs_url=sp_acs_url(),
                           saml_response=saml.b64(xml), relay_state=relay_state or "")


@app.route("/idp/sso")
def idp_sso():
    saml_request = request.args.get("SAMLRequest", "")
    relay_state = request.args.get("RelayState", "")
    if not saml_request:
        return render_template("error.html", message="Missing SAMLRequest."), 400
    if "idp_email" not in session:
        # Authenticate the user first; carry the request through the login form.
        return render_template("idp_login.html", error=None,
                               saml_request=saml_request, relay_state=relay_state)
    return _issue_response(saml_request, relay_state)


@app.route("/idp/login", methods=["POST"])
def idp_login():
    saml_request = request.form.get("SAMLRequest", "")
    relay_state = request.form.get("RelayState", "")
    email = request.form.get("email", "").strip().lower()
    user = db.get_user_by_email(email)
    if user and db.verify_password(request.form.get("password", ""), user["password_hash"]):
        session["idp_email"] = user["email"]
        return _issue_response(saml_request, relay_state)
    return render_template("idp_login.html", error="Invalid email or password.",
                           saml_request=saml_request, relay_state=relay_state)


# ===========================================================================
# (SP) Service Provider
# ===========================================================================

@app.route("/sp/metadata")
def sp_metadata():
    xml = f"""<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{sp_entity()}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{sp_acs_url()}" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"""
    return app.response_class(xml, mimetype="application/xml")


@app.route("/sp/")
def sp_home():
    return render_template("sp_home.html", user=session.get("sp_user"))


@app.route("/sp/login")
def sp_login():
    from urllib.parse import quote
    rid, xml = saml.build_authn_request(sp_entity(), sp_acs_url(), idp_sso_url())
    session["saml_req_id"] = rid   # remembered to match InResponseTo at the ACS
    q = f"SAMLRequest={quote(saml.deflate_b64(xml))}&RelayState={quote('/sp/')}"
    return redirect(idp_sso_url() + "?" + q)


@app.route("/sp/acs", methods=["POST"])
def sp_acs():
    saml_response = request.form.get("SAMLResponse", "")
    if not saml_response:
        return render_template("error.html", message="Missing SAMLResponse."), 400
    try:
        result = saml.validate_response(
            xml=saml.unb64(saml_response),
            idp_cert_pem=idp_keys.CERT_PEM,
            sp_entity_id=sp_entity(),
            acs_url=sp_acs_url(),
            expected_in_response_to=session.get("saml_req_id", ""),
            seen_assertion_ids=SEEN_ASSERTIONS,
        )
    except saml.SamlError as e:
        app.logger.warning("ACS rejected assertion: %s", e)
        return render_template("error.html", message=f"Assertion rejected: {e}"), 400

    session.pop("saml_req_id", None)
    session["sp_user"] = {"nameid": result["nameid"], **result["attributes"]}
    return render_template("sp_result.html", user=session["sp_user"])


# ===========================================================================
# demo
# ===========================================================================

@app.route("/")
def home():
    return render_template("sp_home.html", user=session.get("sp_user"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("sp_home"))


if __name__ == "__main__":
    db.init_schema()
    _ = idp_keys.CERT_PEM  # ensure the IdP key/cert exist at boot
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
