"""
app.py — passwordless login with WebAuthn passkeys.

Four JSON endpoints implement the two ceremonies (each is begin -> finish, with
the server's random challenge held in the session between the two calls):

  POST /register/begin   -> creation options (challenge, rp, user, params)
  POST /register/finish  -> verify attestation, store the public key
  POST /login/begin      -> request options (challenge, allowCredentials)
  POST /login/finish     -> verify assertion signature, establish a session

`/` serves a browser page (works over http://localhost — a WebAuthn secure
context) or the signed-in dashboard. client_example.py exercises the same
endpoints with a software authenticator.
"""

import os
import secrets

from flask import Flask, jsonify, render_template, request, session

import db
import webauthn as wa

RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = "identity-17"
ORIGIN = os.environ.get("ORIGIN", "http://localhost:5000")

app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY is not set (needed for the session cookie).")
app.secret_key = _secret
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1")


def _b(v):
    return wa.b64url_encode(v)


# --- registration -----------------------------------------------------------

@app.route("/register/begin", methods=["POST"])
def register_begin():
    email = (request.get_json(silent=True) or {}).get("email", "").strip().lower()
    if not email:
        return jsonify(error="email required"), 400
    user = db.get_user_by_email(email) or db.get_user_by_id(db.create_user(email, email.split("@")[0]))

    challenge = secrets.token_bytes(32)
    session["reg_challenge"] = _b(challenge)
    session["reg_user_id"] = user["id"]
    return jsonify(
        challenge=_b(challenge),
        rp={"id": RP_ID, "name": RP_NAME},
        user={"id": _b(user["id"].to_bytes(8, "big")), "name": email,
              "displayName": user["name"] or email},
        pubKeyCredParams=[{"type": "public-key", "alg": -7}],  # ES256
        authenticatorSelection={"userVerification": "preferred"},
        attestation="none",
        timeout=60000,
    )


@app.route("/register/finish", methods=["POST"])
def register_finish():
    if "reg_challenge" not in session:
        return jsonify(error="no registration in progress"), 400
    cred = request.get_json(force=True)
    try:
        cred_id, cose_key, count = wa.verify_registration(
            client_data_json=wa.b64url_decode(cred["response"]["clientDataJSON"]),
            attestation_object=wa.b64url_decode(cred["response"]["attestationObject"]),
            expected_challenge=wa.b64url_decode(session["reg_challenge"]),
            expected_origin=ORIGIN, expected_rp_id=RP_ID,
        )
    except wa.WebAuthnError as e:
        return jsonify(error="registration_failed", detail=str(e)), 400

    db.add_credential(cred_id, session["reg_user_id"], cose_key, count)
    session.pop("reg_challenge", None)
    return jsonify(status="ok", credential_id=_b(cred_id))


# --- authentication ---------------------------------------------------------

@app.route("/login/begin", methods=["POST"])
def login_begin():
    email = (request.get_json(silent=True) or {}).get("email", "").strip().lower()
    user = db.get_user_by_email(email)
    if not user:
        return jsonify(error="unknown user"), 404
    cred_ids = db.get_credentials_for_user(user["id"])
    if not cred_ids:
        return jsonify(error="no passkeys registered"), 400

    challenge = secrets.token_bytes(32)
    session["auth_challenge"] = _b(challenge)
    session["auth_user_id"] = user["id"]
    return jsonify(
        challenge=_b(challenge),
        rpId=RP_ID,
        allowCredentials=[{"type": "public-key", "id": _b(cid)} for cid in cred_ids],
        userVerification="preferred",
        timeout=60000,
    )


@app.route("/login/finish", methods=["POST"])
def login_finish():
    if "auth_challenge" not in session:
        return jsonify(error="no login in progress"), 400
    assertion = request.get_json(force=True)
    cred_id = wa.b64url_decode(assertion["id"])
    row = db.get_credential(cred_id)
    if row is None or row["user_id"] != session.get("auth_user_id"):
        return jsonify(error="unknown credential"), 400

    try:
        new_count = wa.verify_assertion(
            client_data_json=wa.b64url_decode(assertion["response"]["clientDataJSON"]),
            authenticator_data=wa.b64url_decode(assertion["response"]["authenticatorData"]),
            signature=wa.b64url_decode(assertion["response"]["signature"]),
            cose_public_key=row["public_key"],
            expected_challenge=wa.b64url_decode(session["auth_challenge"]),
            expected_origin=ORIGIN, expected_rp_id=RP_ID,
            stored_sign_count=row["sign_count"],
        )
    except wa.WebAuthnError as e:
        return jsonify(error="login_failed", detail=str(e)), 401

    db.update_sign_count(cred_id, new_count)
    session.pop("auth_challenge", None)
    session["uid"] = row["user_id"]
    user = db.get_user_by_id(row["user_id"])
    return jsonify(status="ok", email=user["email"])


# --- pages ------------------------------------------------------------------

@app.route("/")
def index():
    user = db.get_user_by_id(session["uid"]) if "uid" in session else None
    return render_template("index.html", user=user, rp_id=RP_ID)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return jsonify(status="ok") if request.method == "POST" else index()


if __name__ == "__main__":
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
