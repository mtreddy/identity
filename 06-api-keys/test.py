"""test.py — checks for 06-api-keys. Exits nonzero on failure."""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402


def main():
    T.clean(HERE)
    seed = T.run(HERE, ["seed.py"])
    keys = re.findall(r"API key:\s*(sk_live_\S+)", seed.stdout)
    billing, analytics = keys[0], keys[1]
    proc, base = T.start_server(HERE)

    def h(key):
        return {"Authorization": f"Bearer {key}"} if key else {}

    st, body = T.get_json(base + "/v1/whoami", headers=h(billing))
    T.check("valid key -> whoami 200", st == 200 and body.get("name") == "billing-agent")

    st, body = T.get_json(base + "/v1/resources", headers=h(billing))
    T.check("billing sees its resources", st == 200 and len(body["resources"]) == 2)

    st, body = T.get_json(base + "/v1/resources", headers=h(analytics))
    T.check("per-client isolation", st == 200 and len(body["resources"]) == 1)

    T.check("no key -> 401", T.get_json(base + "/v1/whoami")[0] == 401)
    T.check("bad key -> 401", T.get_json(base + "/v1/whoami", headers=h("sk_live_bogus"))[0] == 401)

    st, body = T.get_json(base + "/v1/whoami", headers={"X-API-Key": billing})
    T.check("X-API-Key header also works", st == 200)

    # revocation: revoke billing's key (row id 1) -> 401; analytics still 200
    sys.path.insert(0, HERE)
    import db  # noqa: E402
    db.revoke_api_key(1)
    T.check("revoked key -> 401", T.get_json(base + "/v1/whoami", headers=h(billing))[0] == 401)
    T.check("other client unaffected", T.get_json(base + "/v1/whoami", headers=h(analytics))[0] == 200)

    T.finish(proc)


if __name__ == "__main__":
    main()
