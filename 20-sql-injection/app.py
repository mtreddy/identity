"""
app.py — a tiny API exposing VULNERABLE and SAFE variants of the same features,
so you can fire the same attack at both and see one fall and the other hold.

  /vuln/login   /safe/login     — SQLi auth bypass
  /vuln/search  /safe/search    — UNION-based data exfiltration
  /vuln/list    /safe/list      — ORDER BY / identifier injection (allow-list)

Every response echoes the SQL that ran, so the mechanism is visible. The /vuln/*
endpoints are intentionally exploitable — this app is a sandbox for learning
SQL-injection defense, not something to deploy.
"""

import os

from flask import Flask, jsonify, request

import db

app = Flask(__name__)


def _rows(rows):
    return [dict(r) for r in rows]


# --- login: auth bypass -----------------------------------------------------

@app.route("/vuln/login")
def vuln_login():
    rows, sql = db.login_vulnerable(request.args.get("username", ""),
                                    request.args.get("password", ""))
    return jsonify(authenticated=len(rows) > 0, user=_rows(rows)[:1], sql=sql)


@app.route("/safe/login")
def safe_login():
    rows, sql = db.login_safe(request.args.get("username", ""),
                              request.args.get("password", ""))
    return jsonify(authenticated=len(rows) > 0, user=_rows(rows)[:1], sql=sql)


# --- search: UNION exfiltration ---------------------------------------------

@app.route("/vuln/search")
def vuln_search():
    rows, sql = db.search_vulnerable(request.args.get("category", ""))
    return jsonify(results=_rows(rows), sql=sql)


@app.route("/safe/search")
def safe_search():
    rows, sql = db.search_safe(request.args.get("category", ""))
    return jsonify(results=_rows(rows), sql=sql)


# --- list: ORDER BY / identifier injection ----------------------------------

@app.route("/vuln/list")
def vuln_list():
    try:
        rows, sql = db.list_sorted_vulnerable(request.args.get("sort", "name"))
        return jsonify(results=_rows(rows), sql=sql)
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.route("/safe/list")
def safe_list():
    try:
        rows, sql = db.list_sorted_safe(request.args.get("sort", "name"))
        return jsonify(results=_rows(rows), sql=sql)
    except ValueError as e:
        # The allow-list rejected a non-column value before any SQL ran.
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    db.init_schema()
    db.seed()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
