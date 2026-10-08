#!/usr/bin/env python3
"""
Scope probe for a Private Packagist OIDC trusted-publishing credential.

Runs inside the GitHub Actions runner that owns the trusted publisher, so the
exchanged credential never leaves the runner. Results are written to
results-<MODE>.txt and committed back to this public repository, because the
Actions log is not readable without repository admin rights. Only HTTP status
codes, lengths and non-secret metadata are written.

MODE=scope      exchange for the configured package, prove the credential works
                for the operation it exists for, then probe endpoints outside
                the documented scope.
MODE=variation  attempt exchanges the trusted-publisher configuration should
                refuse, with a fresh OIDC token per attempt.
"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HOST = "packagist.com"
BASE = "https://" + HOST
ORG = os.environ.get("ORG", "audit-lab-gt")
PKG = os.environ.get("PKG", "audit-lab/oidc-scope-test")
MODE = os.environ.get("MODE", "scope")
ARTIFACT = os.environ.get("ARTIFACT", "artifact.txt")
TAG = os.environ.get("TAG", MODE)

OUT = []


def say(s=""):
    print(s)
    OUT.append(s)


def oidc_token(audience):
    url = (os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
           + "&audience=" + urllib.parse.quote(audience))
    req = urllib.request.Request(url, headers={
        "Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
        "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["value"]


def exchange(org, pkg):
    """One OIDC token -> one API credential. Returns (status, parsed_body)."""
    try:
        tok = oidc_token("private-packagist-trusted-publishing:" + org)
    except Exception as e:
        return None, "oidc_token_error: " + str(e)[:150]
    req = urllib.request.Request(
        BASE + "/api/oidc/token-exchange/" + org + "/" + pkg,
        data=b"{}", method="POST",
        headers={"Authorization": "Bearer " + tok,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:220]
    except Exception as e:
        return None, str(e)[:200]


def _enc(v):
    return urllib.parse.quote(str(v), safe="-_.~")


def sign(method, path, key, secret, body=None):
    ts = int(time.time())
    nonce = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    params = {"timestamp": str(ts), "cnonce": nonce, "key": key,
              "version": "2", "query": ""}
    if body:
        params["body"] = body
    params = {k: params[k] for k in sorted(params)}
    sts = (method + "\n" + HOST + "\n" + path + "\n"
           + "&".join(_enc(k) + "=" + _enc(v) for k, v in params.items()))
    sig = base64.b64encode(
        hmac.new(secret.encode(), sts.encode(), hashlib.sha256).digest()).decode()
    return ("PACKAGIST-HMAC-SHA256 Key=" + key + ", Timestamp=" + str(ts)
            + ", Cnonce=" + nonce + ", Version=2, Signature=" + sig)


def call(method, path, key, secret, payload=None, raw=None,
         content_type="application/json", extra=None):
    headers = {"User-Agent": "pp-oidc-scope-probe", "Accept": "application/json"}
    if raw is not None:
        body = raw
        headers["Content-Type"] = content_type
    elif payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    elif method in ("POST", "PUT", "PATCH"):
        body = b"{}"
        headers["Content-Type"] = "application/json"
    else:
        body = None
    if extra:
        headers.update(extra)
    headers["Authorization"] = sign(
        method, path, key, secret,
        body.decode("utf-8", "replace") if body else None)
    req = urllib.request.Request(BASE + path, data=body, method=method,
                                headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")[:220]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:220]
    except Exception as e:
        return None, str(e)[:200]


def mask(k, s):
    print("::add-mask::" + k)
    print("::add-mask::" + s)


def header():
    say("tag         : " + TAG)
    say("mode        : " + MODE)
    say("org         : " + ORG)
    say("package     : " + PKG)
    say("repository  : " + os.environ.get("GITHUB_REPOSITORY", "?"))
    say("workflow ref: " + os.environ.get("GITHUB_WORKFLOW_REF", "?"))
    say("environment : " + (os.environ.get("GITHUB_ENVIRONMENT") or "(none)"))
    say("event       : " + os.environ.get("GITHUB_EVENT_NAME", "?"))
    say("run id      : " + os.environ.get("GITHUB_RUN_ID", "?"))
    say("")


# ------------------------------------------------------------------ modes

def variations():
    header()
    say("=== EXCHANGE VARIATIONS (fresh OIDC token per attempt) ===")
    cases = [
        ("configured package", ORG, PKG),
        ("different package, same org", ORG, "audit-lab/other-package"),
        ("other vendor namespace, same org", ORG, "someone-else/oidc-scope-test"),
        ("package name with path chars", ORG, "audit-lab/oidc-scope-test/extra"),
        ("package name url-encoded slash", ORG, "audit-lab%2Foidc-scope-test"),
    ]
    for label, org, pkg in cases:
        st, body = exchange(org, pkg)
        issued = isinstance(body, dict) and "key" in body
        note = ""
        if issued:
            mask(body["key"], body["secret"])
            note = " key_len=%d secret_len=%d" % (len(body["key"]), len(body["secret"]))
        elif isinstance(body, str):
            note = " " + body.replace("\n", " ")[:150]
        say("  %-34s HTTP %-6s issued=%-5s%s" % (label, st, issued, note))


def scope():
    header()
    say("=== EXCHANGE ===")
    st, body = exchange(ORG, PKG)
    say("  POST /api/oidc/token-exchange/%s/%s -> HTTP %s" % (ORG, PKG, st))
    if not (isinstance(body, dict) and "key" in body):
        say("  EXCHANGE FAILED: %s" % str(body)[:220])
        say("  nothing further can be tested")
        return
    key, secret = body["key"], body["secret"]
    mask(key, secret)
    say("  credential issued: key_len=%d secret_len=%d" % (len(key), len(secret)))
    say("")

    say("=== IN-SCOPE CONTROL: the operation this credential exists for ===")
    data = open(ARTIFACT, "rb").read()
    st, b = call("POST", "/api/packages/artifacts/", key, secret, raw=data,
                 content_type="text/plain", extra={"X-FILENAME": "artifact.txt"})
    say("  POST /api/packages/artifacts/            -> %s" % st)
    say("  body: %s" % b.replace("\n", " ")[:170])
    say("")

    say("=== OUT-OF-SCOPE READ PROBE ===")
    say("  documented scope: only endpoints required to publish the artifact")
    for p in ["/api/teams/", "/api/credentials/", "/api/suborganizations/",
              "/api/packages/", "/api/vendor-bundles/",
              "/api/mirrored-repositories/", "/api/customers/",
              "/api/organization/"]:
        st, b = call("GET", p, key, secret)
        say("  GET  %-38s -> %s" % (p, st))
    say("")

    say("=== OUT-OF-SCOPE WRITE PROBE (non-destructive, own organization) ===")
    st, b = call("POST", "/api/teams/", key, secret, payload={
        "name": "oidc-should-not-exist",
        "permissions": {"canEditTeamPackages": False, "canAddPackages": False,
                        "canCreateSuborganizations": False,
                        "canViewVendorCustomers": False,
                        "canManageVendorCustomers": False}})
    say("  POST /api/teams/                         -> %s" % st)
    say("  body: %s" % b.replace("\n", " ")[:170])
    say("")

    say("=== PRIVILEGE-ESCALATION PROBE: can it mint a wider credential? ===")
    st, b = call("POST", "/api/credentials/", key, secret, payload={
        "description": "oidc-should-not-exist", "type": "http-basic",
        "domain": "example.com", "username": "audit", "credential": "x"})
    say("  POST /api/credentials/                   -> %s" % st)
    say("  body: %s" % b.replace("\n", " ")[:170])
    say("")

    say("=== TOKEN-SCOPE PROBE: can it mint a composer token? ===")
    st, b = call("POST", "/api/tokens/", key, secret, payload={
        "description": "oidc-should-not-exist", "access": "update"})
    say("  POST /api/tokens/                        -> %s" % st)
    say("  body: %s" % b.replace("\n", " ")[:170])


if __name__ == "__main__":
    try:
        if MODE == "variation":
            variations()
        else:
            scope()
    finally:
        path = "results-%s.txt" % TAG
        with open(path, "w") as f:
            f.write("\n".join(OUT) + "\n")
        print("wrote " + path)
