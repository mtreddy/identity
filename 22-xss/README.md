# 22 — XSS attack vs. defense

A cross-cutting web-security demo (same `vuln`-vs-`safe` style as
`20-sql-injection` and `21-csrf`). **XSS** (Cross-Site Scripting) is when a page
renders attacker-controlled input as **HTML/JavaScript**, so the attacker's code
runs in the victim's browser — able to act as the user, read page data, or
steal non-`HttpOnly` cookies.

The same input is rendered two ways:

| Endpoint | Rendering |
|----------|-----------|
| `/vuln/search`, `/vuln/comments` | input concatenated into HTML — **not escaped** |
| `/safe/search`, `/safe/comments` | rendered through Jinja (**auto-escaped**) + a **CSP** |

> The `/vuln` endpoints are intentionally exploitable — a sandbox for the fix.

## The three XSS types
- **Reflected** — input echoed straight back in the response
  (`/vuln/search?q=<script>…`).
- **Stored** — input saved and served to every later viewer
  (`/vuln/comments`) — the most dangerous.
- **DOM-based** — happens entirely in the browser: JS writes attacker input to a
  dangerous sink. `/dom` compares `innerHTML` (vulnerable) vs `textContent`
  (safe). This one never touches the server, so the fix is choosing a safe sink.

## Files

| File | Role |
|------|------|
| `app.py` | `/vuln/*` (raw HTML) and `/safe/*` (Jinja-escaped + CSP) endpoints; HttpOnly session cookie |
| `templates/` | index, escaped comments page, DOM-sink comparison |
| `client_example.py` | sends a payload and reports "raw (would execute)" vs "encoded (inert)" |

## Run it

```bash
cd 22-xss
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
COOKIE_SECURE=0 python app.py            # http://127.0.0.1:5000

python client_example.py                 # headless: raw vs encoded
```

In a browser, open `/` and click the payload links: on `/vuln/*` the
`alert(document.domain)` fires; on `/safe/*` it shows up as harmless text.

## The layered defenses

| Layer | Where | What it does |
|-------|-------|--------------|
| **Contextual output encoding** | `/safe` (Jinja autoescaping) | the primary fix — user input is rendered as **text**, so `<script>` becomes `&lt;script&gt;` and never parses as a tag |
| **Content-Security-Policy** | `/safe` responses (`script-src 'self'`) | a second line — even if an encoding bug slips through, the browser refuses to run inline/injected script |
| **`HttpOnly` cookie** | the session cookie | limits the damage — a working XSS still can't read the session cookie via `document.cookie` |

### The encoding footgun
Jinja autoescapes `{{ x }}` by **default** — the vulnerable endpoints here had to
go *out of their way* (raw f-strings) to be unsafe. In real templates the danger
is deliberately disabling that: `{{ user_input | safe }}`,
`Markup(user_input)`, `render_template_string` built from user input, or React's
`dangerouslySetInnerHTML`. Treat those as red flags.

### Encoding is context-dependent
HTML-escaping is right for element text. Input placed into other contexts needs
different encoding: an HTML **attribute**, a **URL**, inside a `<script>` block,
or CSS each have their own rules. "Escape on output, for the context you're
outputting into" — don't rely on a single escape everywhere.

## Threats addressed
| Threat | Defense |
|--------|---------|
| Reflected/stored script execution | output encoding (autoescaping) on `/safe` |
| Injected inline script running | Content-Security-Policy |
| Session-cookie theft via `document.cookie` | `HttpOnly` cookie |
| DOM sink injection | safe sink (`textContent`, not `innerHTML`) |

## Notes / further hardening
Sanitize rich HTML (if you must allow it) with a vetted allow-list sanitizer
rather than regex; tighten CSP (nonces/hashes instead of `'self'` for inline);
set `X-Content-Type-Options: nosniff` (done on `/safe`); and remember XSS
defeats CSRF tokens (an in-page script can read them) — so fixing XSS also
protects `21-csrf`.
