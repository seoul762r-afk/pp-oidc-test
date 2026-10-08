#!/usr/bin/env python3
"""
Scope probe for a Private Packagist OIDC trusted-publishing credential.

Runs inside the GitHub Actions runner that owns the trusted publisher, so the
exchanged credential never leaves the runner. Results are written to
results-<TAG>.txt and committed back to this public repository, because the
Actions log is not readable without repository admin rights. Only HTTP status
codes, lengths and non-secret metadata are written.

MODE=scope      exchange, prove the credential performs the operation it exists
                for, then probe outside the documented scope.
MODE=variation  attempt exchanges the trusted-publisher configuration should
                refuse, with a fresh OIDC token per attempt.

The in-scope control must SUCCEED before any denial is interpreted: a
credential that is broken for everything would produce denials too.
"""
import base64
import gzip
import hashlib
import hmac
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

HOST = "packagist.com"
BASE = "https://" + HOST
ORG = os.environ.get("ORG", "audit-lab-gt")
PKG = os.environ.get("PKG", "audit-lab/oidc-scope-test")
OTHER_PKG = os.environ.get("OTHER_PKG", "audit-lab/not-the-configured-package")
MODE = os.environ.get("MODE", "scope")
TAG = os.environ.get("TAG", MODE)
ARTIFACT = os.environ.get("ARTIFACT", "artifact.zip")
ARTIFACT_CT = os.environ.get("ARTIFACT_CT", "application/zip")

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


def _enc_bytes(b):
    """Percent-encode raw bytes the way PHP's http_build_query does.

    The body of a file upload is binary. Decoding it as text before signing
    corrupts the bytes and the server answers 400 "Invalid signature", so the
    canonical string is built from the exact bytes that go on the wire.
    """
    return urllib.parse.quote_from_bytes(b, safe="-_.~")


def sign(method, path, key, secret, body_bytes=None):
    ts = int(time.time())
    nonce = uuid.uuid4().hex + uuid.uuid4().hex[:8]
    pairs = [
        ("cnonce", _enc(nonce)),
        ("key", _enc(key)),
        ("query", _enc("")),
        ("timestamp", _enc(ts)),
        ("version", _enc("2")),
    ]
    if body_bytes:
        pairs.append(("body", _enc_bytes(body_bytes)))
    pairs.sort(key=lambda kv: kv[0])
    sts = (method + "\n" + HOST + "\n" + path + "\n"
           + "&".join(k + "=" + v for k, v in pairs))
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
    headers["Authorization"] = sign(method, path, key, secret, body)
    req = urllib.request.Request(BASE + path, data=body, method=method,
                                headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode("utf-8", "replace")[:250]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:250]
    except Exception as e:
        return None, str(e)[:220]


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
    say("event       : " + os.environ.get("GITHUB_EVENT_NAME", "?"))
    say("run id      : " + os.environ.get("GITHUB_RUN_ID", "?"))
    say("")


def variations():
    header()
    say("=== EXCHANGE VARIATIONS (fresh OIDC token per attempt) ===")
    cases = [
        ("configured package", ORG, PKG),
        ("different package, same org", ORG, OTHER_PKG),
        ("other vendor namespace, same org", ORG, "someone-else/oidc-scope-test"),
        ("package name with path chars", ORG, PKG + "/extra"),
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


def build_artifact():
    """Build the artifact in memory.

    The endpoint expects a ZIP containing composer.json (the docs' example
    artifact is artifact.zip). A gzip is accepted by the transport but then
    fails with "internal corruption of phar", so the probe must not depend on
    the workflow's plain-text prepare step. Generating the bytes here keeps the
    probe self-contained.
    """
    composer = {
        "name": PKG,
        "description": "Private Packagist OIDC scope test artifact",
        "version": "1.0.0",
        "type": "library",
        "license": "MIT",
        "require": {},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("composer.json", json.dumps(composer, indent=2))
    return buf.getvalue()


def scope():
    header()

    say("=== STEP 1: EXCHANGE (must succeed, or nothing below is interpretable) ===")
    st, body = exchange(ORG, PKG)
    say("  POST /api/oidc/token-exchange/%s/%s -> HTTP %s" % (ORG, PKG, st))
    if not (isinstance(body, dict) and "key" in body):
        say("  EXCHANGE FAILED: %s" % str(body)[:220])
        say("  RUN VOID: no credential to test with")
        return
    key, secret = body["key"], body["secret"]
    mask(key, secret)
    say("  credential issued: key_len=%d secret_len=%d" % (len(key), len(secret)))
    say("")

    say("=== STEP 2: IN-SCOPE CONTROL - publish an artifact ===")
    say("  the operation this credential exists for must SUCCEED, otherwise")
    say("  every later denial is uninterpretable")
    data = build_artifact()
    say("  artifact: %s, %d bytes" % (ARTIFACT, len(data)))
    st_up, b = call("POST", "/api/packages/artifacts/", key, secret, raw=data,
                    content_type=ARTIFACT_CT,
                    extra={"X-FILENAME": ARTIFACT})
    say("  POST /api/packages/artifacts/            -> %s" % st_up)
    say("  body: %s" % b.replace("\n", " ")[:200])
    artifact_id = None
    try:
        j = json.loads(b)
        artifact_id = j.get("id") or (j.get("artifact") or {}).get("id")
    except Exception:
        pass
    say("  artifact id: %s" % artifact_id)
    say("")

    if artifact_id:
        st_pkg, b2 = call("POST", "/api/packages/", key, secret, payload={
            "repoType": "artifact", "artifactIds": [artifact_id]})
        say("  POST /api/packages/ (create artifact package) -> %s" % st_pkg)
        say("  body: %s" % b2.replace("\n", " ")[:200])
        say("")

    say("=== STEP 3: CROSS-PACKAGE WRITE (same operation, different package) ===")
    say("  the credential was issued for %s; can it publish into another package?" % PKG)
    st_cross, b3 = call("POST", "/api/packages/%s/artifacts/" % OTHER_PKG,
                        key, secret, raw=data, content_type=ARTIFACT_CT,
                        extra={"X-FILENAME": ARTIFACT})
    say("  POST /api/packages/%s/artifacts/ -> %s" % (OTHER_PKG, st_cross))
    say("  body: %s" % b3.replace("\n", " ")[:200])
    say("")

    st_sub, b4 = call("POST", "/api/suborganizations/sub-a/packages/artifacts/",
                      key, secret, raw=data, content_type=ARTIFACT_CT,
                      extra={"X-FILENAME": ARTIFACT})
    say("  POST /api/suborganizations/sub-a/packages/artifacts/ -> %s" % st_sub)
    say("  body: %s" % b4.replace("\n", " ")[:200])
    say("")

    say("=== STEP 4: OUT-OF-SCOPE READ PROBE ===")
    say("  documented scope: only endpoints required to publish the artifact")
    for p in ["/api/teams/", "/api/credentials/", "/api/suborganizations/",
              "/api/packages/", "/api/vendor-bundles/",
              "/api/mirrored-repositories/", "/api/customers/",
              "/api/organization/"]:
        st_r, b5 = call("GET", p, key, secret)
        say("  GET  %-38s -> %-5s %s" % (p, st_r, b5.replace("\n", " ")[:60]))
    say("")

    say("=== STEP 5: OUT-OF-SCOPE WRITE PROBE (own organization, non-destructive) ===")
    for label, path, payload in [
        ("create team", "/api/teams/", {
            "name": "oidc-should-not-exist",
            "permissions": {"canEditTeamPackages": False, "canAddPackages": False,
                            "canCreateSuborganizations": False,
                            "canViewVendorCustomers": False,
                            "canManageVendorCustomers": False}}),
        ("create credential", "/api/credentials/", {
            "description": "oidc-should-not-exist", "type": "http-basic",
            "domain": "example.com", "username": "audit", "credential": "x"}),
        ("create composer token", "/api/tokens/", {
            "description": "oidc-should-not-exist", "access": "update"}),
    ]:
        st_w, b6 = call("POST", path, key, secret, payload=payload)
        say("  %-22s POST %-24s -> %-5s %s" % (
            label, path, st_w, b6.replace("\n", " ")[:70]))
    say("")

    say("=== STEP 6: REPEAT the in-scope control (stability) ===")
    st_rep, b7 = call("POST", "/api/packages/artifacts/", key, secret, raw=data,
                      content_type=ARTIFACT_CT,
                      extra={"X-FILENAME": ARTIFACT})
    say("  POST /api/packages/artifacts/ (repeat)  -> %s" % st_rep)
    say("  body: %s" % b7.replace("\n", " ")[:200])


if __name__ == "__main__":
    try:
        if MODE == "variation":
            variations()
        else:
            scope()
    except Exception as exc:
        # record the failure in the results file rather than dying silently
        import traceback
        say("")
        say("=== PROBE EXCEPTION ===")
        say("  " + type(exc).__name__ + ": " + str(exc)[:300])
        say("  traceback tail:")
        for line in traceback.format_exc().splitlines()[-6:]:
            say("    " + line[:160])
    finally:
        path = "results-%s.txt" % TAG
        with open(path, "w") as f:
            f.write("\n".join(OUT) + "\n")
        print("wrote " + path)
