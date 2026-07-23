"""
testlib.py — a tiny shared harness for the per-mechanism `test.py` files.

Each mechanism has a self-contained `test.py` that asserts both the happy path
and the security-negative checks that were verified while building it. They use
these helpers to start the app, make HTTP calls, record PASS/FAIL, and exit
nonzero if anything fails. Kept dependency-free (stdlib only).

A test.py adds the repo root to sys.path and imports this:

    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import testlib as T
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_checks = []


def check(name, ok, detail=""):
    """Record a check; print PASS/FAIL (with detail on failure)."""
    ok = bool(ok)
    _checks.append((name, ok))
    line = f"  [{'PASS' if ok else 'FAIL'}] {name}"
    if detail and not ok:
        line += f"  -- {detail}"
    print(line)
    return ok


def start_server(here, env_extra=None, args=("app.py",), port=None):
    """Launch the mechanism's server as a subprocess. Returns (proc, base_url)."""
    port = str(port or os.environ.get("TEST_PORT") or _free_port())
    env = {**os.environ, "PORT": port}
    env.setdefault("COOKIE_SECURE", "0")   # tests run over http
    if env_extra:
        env.update(env_extra)
    proc = subprocess.Popen(
        [sys.executable, *args], cwd=here, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    scheme = "https" if env.get("USE_ADHOC_TLS") == "1" else "http"
    base = f"{scheme}://127.0.0.1:{port}"
    _wait_ready(base, proc)
    return proc, base


def run(here, args, env_extra=None):
    """Run a helper script (e.g. seed.py) to completion."""
    env = {**os.environ}
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, *args], cwd=here, env=env,
                          capture_output=True, text=True)


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_ready(base, proc, tries=60):
    for _ in range(tries):
        if proc.poll() is not None:
            raise SystemExit(f"server exited early (code {proc.returncode})")
        try:
            urllib.request.urlopen(base + "/", timeout=1)
            return
        except urllib.error.HTTPError:
            return          # any HTTP status means it's up
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    raise SystemExit("server did not become ready")


# --- HTTP helpers (stdlib) --------------------------------------------------

def http(method, url, data=None, headers=None, json_body=None, ctx=None,
         allow_redirects=True):
    """Make a request. `data` is a dict (form-encoded); `json_body` a dict
    (JSON). Returns (status, headers, text)."""
    body = None
    hdrs = dict(headers or {})
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    opener_args = []
    if not allow_redirects:
        opener_args.append(_NoRedirect())
    if ctx is not None:
        opener_args.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*opener_args)
    try:
        r = opener.open(req)
        return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def get_json(url, headers=None, ctx=None):
    st, _, text = http("GET", url, headers=headers, ctx=ctx)
    return st, (json.loads(text) if text else {})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def finish(proc=None):
    """Tear down and exit nonzero if any check failed."""
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    n = len(_checks)
    failed = [name for name, ok in _checks if not ok]
    print(f"\n{n - len(failed)}/{n} checks passed"
          + (f"  ({len(failed)} FAILED: {', '.join(failed)})" if failed else ""))
    sys.exit(1 if failed else 0)
