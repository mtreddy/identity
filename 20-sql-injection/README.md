# 20 — SQL injection defense

The security foundation under every other mechanism here: they all query SQLite,
and they all use **parameterized queries** — this directory shows *why*, by
putting a **vulnerable** and a **safe** version of the same features side by side
and firing real exploits at both.

> The `/vuln/*` endpoints are intentionally exploitable. This is a **sandbox for
> learning defense**, running against its own local SQLite — not something to
> deploy.

## The one rule
> **Never build SQL by concatenating/formatting untrusted input into the query
> string. Pass values as bound parameters (`?`) so the driver treats them as
> DATA, never as SQL.**

```python
# DANGER — input becomes part of the SQL:
f"SELECT ... WHERE username = '{username}'"

# SAFE — input is a bound parameter (data):
conn.execute("SELECT ... WHERE username = ?", (username,))
```

## Files

| File | Role |
|------|------|
| `db.py` | the same three queries in **VULNERABLE** (string-built) and **SAFE** (parameterized/allow-listed) form |
| `app.py` | `/vuln/*` and `/safe/*` endpoints; each echoes the SQL that ran |
| `client_example.py` | fires four attacks at both variants |
| `seed.py` | resets the demo DB (users `admin`/`alice`/`bob`, some products) |

## Run it

```bash
cd 20-sql-injection
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python app.py            # seeds + serves http://127.0.0.1:5000

# in another shell:
python client_example.py
```

Or by hand — the classic auth bypass:

```bash
# vulnerable: logs in as admin with NO valid password
curl 'http://127.0.0.1:5000/vuln/login?username=admin%27%20--%20&password=x'
# safe: rejected — the whole string is treated as a username
curl 'http://127.0.0.1:5000/safe/login?username=admin%27%20--%20&password=x'
```

## The four attacks (and why safe holds)

1. **Auth bypass** — `username = admin' -- ` comments out the password check.
   Vulnerable → logs in as admin. Safe → the literal string `admin' -- ` is just
   a username that doesn't exist → not authenticated.
2. **Tautology** — `x' OR '1'='1' -- ` makes the `WHERE` always true and returns
   the first user (admin). Safe → treated as data, matches nothing.
3. **UNION exfiltration** — a product search of
   `none' UNION SELECT username, secret_note FROM users -- ` returns **user
   secrets** through the product endpoint. Safe → the payload is one literal
   category value → no rows.
4. **ORDER BY / identifier injection** — `sort` is a column *name*, and column
   names **can't be bound as parameters** (`?` only binds values). The vulnerable
   version concatenates it → arbitrary SQL expression runs. The safe version
   validates `sort` against an **allow-list** (`{name, price}`) and rejects
   anything else with `400`.

## The layered defenses (defense in depth)

| Layer | What it does |
|-------|--------------|
| **Parameterized queries / prepared statements** | the primary fix — values are never parsed as SQL. Covers ~all value-position injection. |
| **Allow-list for identifiers** | table/column/`ORDER BY` names can't be parameters, so validate them against a fixed set. |
| **Input validation** | type/format/length checks reduce the attack surface (but are *not* a substitute for parameters). |
| **Least-privilege DB account** | the app's DB user should only have the rights it needs — so an injection can't `DROP`, read other schemas, or write files. |
| **Use an ORM / query builder carefully** | ORMs parameterize by default — but raw-SQL escape hatches (`.raw()`, string `text()`) reintroduce the risk. |

### Driver note (accurate, and easy to get wrong)
Python's `sqlite3` **`execute()` runs only one statement**, so the classic
*stacked* query `'; DROP TABLE users; --` fails here (you'd need `executescript`).
That's a driver quirk, **not** a defense you can rely on — many databases/drivers
(MySQL multi-statements, some connectors) *do* allow stacked queries. Assume they
do, and parameterize.

## Relation to the rest of this repo
Every mechanism's `db.py` already follows the safe pattern — parameterized
queries throughout (called out as "done well" back in `01-login-password`). This
directory is the explicit, attackable demonstration of the rule they all follow.
