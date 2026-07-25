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

**Cross-Site Scripting (XSS)** is a vulnerability where a web application takes untrusted, attacker-controlled input and renders it directly into a web page as executable HTML or JavaScript.

When a victim views the compromised page, the attacker's malicious script runs within their browser. Because the script runs in the context of the user's active session, the attacker can hijack their session, read sensitive page data, perform actions on their behalf, or steal their cookies.

Based on the [22-xss repository module](https://github.com/mtreddy/identity/tree/main/22-xss) you are viewing, here are the mechanics of the three primary types of XSS and how they are mitigated:

### The Three Types of XSS

1. **Reflected XSS:** The malicious payload is part of the user's request (like a URL parameter) and the server echoes it straight back in the HTTP response.
* *Example:* An attacker sends a victim a link to `[example.com/search?q=](https://example.com/search?q=)<script>stealCookies()</script>`. The server blindly inserts the `q` parameter into the page HTML, executing the script.


2. **Stored XSS:** The most dangerous variant. The attacker's payload is permanently saved to the target server's database (like a forum post, user profile, or comment section).
* *Example:* An attacker submits a comment containing a `<script>` payload. Every subsequent user who views that comment section will unknowingly execute the payload.


3. **DOM-based XSS:** This happens entirely within the browser on the client side, never touching the server. It occurs when a page's legitimate JavaScript takes data from an attacker-controllable source (like the URL hash) and passes it to a dangerous "sink" that executes it.
* *Example:* JavaScript dynamically setting `element.innerHTML = userInput`.



### The Layered Defenses

Defending against XSS requires a defense-in-depth strategy, as a single failure can lead to full compromise.

* **Contextual Output Encoding (Primary Defense):** Before untrusted data is rendered into an HTML document, it must be escaped so the browser interprets it purely as text, not as executable code. For example, `<script>` becomes `&lt;script&gt;`.
* *Note:* The encoding must match the context. Escaping for an HTML body is different from escaping data inside a JavaScript variable, a CSS block, or an HTML attribute. Modern templating engines (like Jinja, React, or Angular) often do this automatically unless explicitly disabled (e.g., using `dangerouslySetInnerHTML`).


* **Content-Security-Policy (CSP):** A secondary layer of defense enforced by the browser. By sending a `Content-Security-Policy` HTTP header, developers can strictly define which domains the browser is allowed to load scripts from, and explicitly forbid the execution of inline scripts (`<script>...</script>`). If an XSS payload slips through the encoding defense, a strong CSP will block it from running.
* **Safe DOM Sinks:** To prevent DOM-based XSS, front-end code must avoid dangerous sinks like `innerHTML` and instead use safe alternatives like `textContent`, which inherently treats the input as text.
* **HttpOnly Cookies:** While this doesn't stop XSS from executing, setting the `HttpOnly` flag on sensitive session cookies prevents JavaScript from accessing them via `document.cookie`. This limits the attacker's ability to easily steal the victim's session token and exfiltrate it.
