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

**SQL Injection (SQLi)** is a critical vulnerability that occurs when an application takes untrusted data (like user input from a web form or API request) and dynamically inserts it directly into a database query. Instead of treating the input as plain data, the database engine is tricked into interpreting it as executable SQL commands.

When conducting software security audits, this is often one of the first vulnerabilities to look for, especially in backend codebases where raw queries are constructed.

Based on the [20-sql-injection](https://github.com/mtreddy/identity/blob/main/20-sql-injection/README.md) repository module you are viewing, here is an elaboration on the mechanics, common attack vectors, and how to defend against them.

### The Core Flaw: Mixing Code and Data

The vulnerability stems entirely from string concatenation or interpolation. If a backend (like a Python application using SQLite) builds a query like this:

```python
# DANGER: The input is formatted directly into the string
username = request.form['username']
query = f"SELECT * FROM users WHERE username = '{username}'"

```

If an attacker supplies `admin' --` as their username, the query becomes:
`SELECT * FROM users WHERE username = 'admin' --'`

The database sees the quote `'`, which closes the string, and then sees `--`, which is the SQL comment indicator. Everything after that is ignored, effectively stripping away password checks and logging the attacker in as the administrator.

### Common Attack Vectors

The repository outlines four classic ways attackers exploit this behavior:

1. **Authentication Bypass:** (The `admin' --` example above). By prematurely closing the input string and commenting out the rest of the query, the attacker forces the system to evaluate only the first part of the `WHERE` clause.
2. **Tautology:** An attacker inputs `x' OR '1'='1' --`. The query becomes `WHERE username = 'x' OR '1'='1'`. Because 1 always equals 1, the condition evaluates to true for every row in the table, often returning the first user record (typically the admin).
3. **UNION Exfiltration:** If the injection point is in a search feature (like looking up products), an attacker can append a `UNION SELECT` statement. For example: `none' UNION SELECT username, secret_note FROM users --`. This forces the database to combine the legitimate search results with a completely different query, leaking sensitive data (like user secrets) out through the application's UI.
4. **Identifier Injection (ORDER BY):** Sometimes inputs aren't values, but structural parts of the query, like a column name for sorting (`ORDER BY {user_input}`). This is particularly dangerous because column names cannot be parameterized.

*(Note: While some attackers try "stacked queries" like `; DROP TABLE users;`, Python's `sqlite3` `execute()` method inherently blocks multiple statements. However, as the documentation notes, this is a specific driver quirk, not a reliable security boundary, as other databases and connectors will happily execute the dropped table command).*

### Defense in Depth

When architecting or reviewing a system for security, mitigating SQLi requires strict adherence to data separation:

* **The Golden Rule — Parameterized Queries:** You must use bound parameters provided by the database driver.
* **Safe Python Example:** `conn.execute("SELECT * FROM users WHERE username = ?", (username,))`
* By passing the query structure and the data separately, the database driver ensures the input is treated strictly as a literal value, not as executable syntax. If an attacker passes `admin' --`, the database searches for a user whose literal name is exactly `admin' --`.


* **Allow-listing for Identifiers:** Because you cannot parameterize structural identifiers like table names or `ORDER BY` columns, you must validate the input against a strict allow-list. If the application expects to sort by `name` or `price`, any other input should be immediately rejected with a 400 Bad Request.
* **Least-Privilege DB Accounts:** The database user credential utilized by the application should only have the minimum permissions necessary to function. It should not have `DROP` privileges, cross-schema read access, or file-writing capabilities, limiting the "blast radius" if an injection flaw is discovered.
* **Careful ORM Usage:** Object-Relational Mappers (ORMs) handle parameterization automatically for most queries. However, raw SQL escape hatches (like `.raw()` or `text()`) reintroduce the risk and must be heavily scrutinized during code reviews.
