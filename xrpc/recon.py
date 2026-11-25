"""xrpc.recon - extracted from the original xploitrpc monolith."""
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
    is_disabled_fault, describe_fault,
    SEVERITY_ORDER, SEVERITY_COLOR,
    DEFAULT_UA, DEFAULT_TIMEOUT, BANNER_DELAY, __version__,
)
from .payloads import CLUE_KEYWORDS
from .data import module_dump





def module_probe(client: RPCClient, state: "State") -> Dict[str, Any]:
    """Confirm the endpoint exists, is XML-RPC, and report what it exposes."""
    head("Endpoint probe: %s" % client.url)
    report: Dict[str, Any] = {"url": client.url}

    # 1. Plain HTTP GET. WordPress answers 405 to a GET on xmlrpc.php.
    try:
        status, headers, body = client.http_probe("GET")
        report["get_status"] = status
        report["server"] = headers.get("server", "?")
        report["powered_by"] = headers.get("x-powered-by", "?")
        kv("GET status", status)
        kv("Server", report["server"])
        kv("X-Powered-By", report["powered_by"])

        # Identify what sits in front of WordPress. A WAF changes how every
        # later result should be read, so establish it first.
        stack = wpcompat.detect_stack(headers, body, status)
        report["stack"] = {
            "detected": stack.detected,
            "server": stack.server,
            "powered_by": stack.powered_by,
            "cdn_cache": stack.cdn_cache,
        }
        if stack.detected:
            kv("Edge / WAF", stack.summary())
            for note_text in stack.notes:
                note(note_text)
        if stack.cdn_cache:
            kv("CDN cache", stack.cdn_cache)

        if status == 405:
            ok("405 Method Not Allowed on GET - classic WordPress xmlrpc.php signature.")
        elif status == 200:
            warn("GET returned 200. Either not WordPress, or a proxy is rewriting responses.")
        elif status == 404:
            bad("404 on GET. The endpoint path is probably wrong.")
        elif status in (401, 403):
            warn("HTTP %d - access control in front of the endpoint." % status)
        elif status == 429:
            bad("HTTP 429 - rate limited before we sent a single XML-RPC call.")
            retry = wpcompat.parse_retry_after(headers)
            if retry is not None:
                note("Retry-After: %.0fs" % retry)
    except TransportError as exc:
        bad(str(exc))
        report["reachable"] = False
        return report

    report["reachable"] = True

    # 2. Does it actually speak XML-RPC?
    try:
        res = client.call("system.listMethods")
        methods = res.value if isinstance(res.value, list) else []
        report["xmlrpc"] = True
        report["method_count"] = len(methods)
        report["methods"] = methods
        state.methods = methods
        ok("XML-RPC is live: %d methods advertised." % len(methods))
        kv("Response time", "%.3fs" % res.elapsed)
        kv("Payload size", "%d bytes" % res.bytes_in)
    except RPCFault as exc:
        report["xmlrpc"] = True
        report["method_count"] = 0
        if is_disabled_fault(exc):
            bad("XML-RPC is installed but DISABLED: %s" % exc.message)
            report["disabled"] = True
        else:
            warn("Server answered with a fault: %s" % describe_fault(exc))
        return report
    except ProtocolError as exc:
        report["xmlrpc"] = False
        bad("Endpoint is not XML-RPC: %s" % exc)
        # Say what it actually was, so a WAF block is not mistaken for a
        # missing endpoint.
        kind, detail = wpcompat.classify_body(
            (getattr(exc, "raw_body", b"") or b"")
        )
        report["response_kind"] = kind
        if kind != wpcompat.ResponseKind.EMPTY:
            note("Response classified as: %s (%s)" % (kind, detail))
            if kind == wpcompat.ResponseKind.CHALLENGE:
                bad("A bot challenge answered instead of WordPress.")
                warn("Your requests are being filtered, not refused. The endpoint")
                warn("may well exist - this response proves nothing about it.")
                warn("Slow down (--delay), change the User-Agent, or test from an")
                warn("IP the site allows. Do not read this as 'no XML-RPC'.")
                report["challenged"] = True
            elif kind == wpcompat.ResponseKind.THROTTLED:
                bad("You are being rate limited.")
                retry = wpcompat.parse_retry_after(
                    getattr(exc, "headers", {}) or {}
                )
                if retry is not None:
                    note("Retry-After: %.0fs" % retry)
                warn("Back off and retry with --delay. This is not a finding")
                warn("about the site's XML-RPC configuration.")
                report["throttled"] = True
            elif kind == wpcompat.ResponseKind.HTML:
                warn("An HTML page here usually means a WAF, a challenge, or a")
                warn("404 - not that XML-RPC is absent. Re-check with --discover.")
        return report
    except TransportError as exc:
        report["xmlrpc"] = False
        bad(str(exc))
        return report

    # 3. Capabilities - tells us whether multicall batching is on the table.
    try:
        caps = client.call_value("system.getCapabilities")
        if isinstance(caps, dict):
            report["capabilities"] = caps
            for key in sorted(caps):
                kv(key, caps[key])
            if "system.multicall" in caps:
                ok("system.multicall is supported - batched auth testing is available.")
    except RPCError:
        warn("system.getCapabilities unavailable (introspection restricted).")

    # 4. WordPress-specific tell: demo.sayHello only exists on WP.
    try:
        hello = client.call_value("demo.sayHello")
        report["wordpress"] = True
        ok("demo.sayHello responded %r - this is WordPress." % hello)
    except RPCError:
        report["wordpress"] = False
        note("demo.sayHello absent - not WordPress, or the demo methods are stripped.")

    state.probe = report
    return report


def module_list_methods(client: RPCClient, state: "State", pattern: Optional[str] = None) -> List[str]:
    head("XML-RPC method inventory")
    try:
        methods = client.call_value("system.listMethods")
    except RPCFault as exc:
        bad("Cannot list methods: %s" % describe_fault(exc))
        return []
    except RPCError as exc:
        bad(str(exc))
        return []

    if not isinstance(methods, list):
        bad("Unexpected reply shape: %r" % type(methods))
        return []

    if pattern:
        rx = re.compile(pattern, re.I)
        methods = [m for m in methods if rx.search(m)]

    # Group by namespace so the output is readable at 80+ methods.
    groups: Dict[str, List[str]] = {}
    for m in methods:
        ns = m.split(".")[0] if "." in m else "(root)"
        groups.setdefault(ns, []).append(m)

    for ns in sorted(groups):
        print()
        print(Term.paint("  %s (%d)" % (ns, len(groups[ns])), "bold", "cyan"))
        for m in sorted(groups[ns]):
            print("    " + m)

    print()
    ok("%d methods%s." % (len(methods), " matching %r" % pattern if pattern else ""))
    state.methods = methods
    return methods


def module_fingerprint(client: RPCClient, state: "State") -> Dict[str, Any]:
    """Identify WordPress version, PHP, plugins and blog configuration."""
    head("Fingerprint")
    fp: Dict[str, Any] = {}

    try:
        status, headers, _ = client.http_probe("GET")
        fp["server"] = headers.get("server")
        fp["php"] = headers.get("x-powered-by")
        if fp["server"]:
            kv("Server", fp["server"])
        if fp["php"]:
            kv("PHP", fp["php"])
    except TransportError:
        pass

    # WordPress core version via readme.html - present on default installs.
    base = client.url.rsplit("/", 1)[0] + "/"
    for probe_path, label in (("readme.html", "readme.html"), ("wp-includes/version.php", "version.php")):
        try:
            req = urllib.request.Request(
                urllib.parse.urljoin(base, probe_path),
                headers={"User-Agent": client.user_agent},
            )
            with client._opener.open(req, timeout=client.timeout) as resp:
                body = resp.read(20000).decode("utf-8", errors="replace")
            m = re.search(r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", body)
            if m:
                fp["wp_version"] = m.group(1)
                ok("WordPress %s (leaked by %s)" % (m.group(1), label))
                break
        except Exception:
            continue

    # The authoritative answer: wp.getOptions exposes software_version.
    if state.has_creds():
        try:
            if not state.blog_id:
                blogs = client.call_value("wp.getUsersBlogs", state.username, state.password)
                if isinstance(blogs, list) and blogs:
                    state.blog_id = str(blogs[0].get("blogid") or blogs[0].get("blog_id") or "")
                    ok("Resolved blog_id=%s" % state.blog_id)
            opts = client.call_value(
                "wp.getOptions", state.blog_id, state.username, state.password,
                ["software_version", "blog_title", "blog_url", "users_can_register",
                 "default_role", "blog_public", "admin_url", "login_url"],
            )
            if isinstance(opts, dict):
                fp["options"] = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in opts.items()}
                for k, v in fp["options"].items():
                    kv(k, v)
                if fp["options"].get("software_version"):
                    ok("WordPress %s (authoritative, via wp.getOptions)" % fp["options"]["software_version"])
                if str(fp["options"].get("users_can_register")) in ("1", "True", "true"):
                    warn("Open registration is enabled - user enumeration is trivial.")
        except RPCError as exc:
            note("wp.getOptions failed: %s" % exc)
    else:
        note("No credentials - version via wp.getOptions not available.")

    # Plugin/theme hints from the rendered homepage.
    try:
        req = urllib.request.Request(base, headers={"User-Agent": client.user_agent})
        with client._opener.open(req, timeout=client.timeout) as resp:
            html = resp.read(400000).decode("utf-8", errors="replace")
        plugins = sorted(set(re.findall(r"/wp-content/plugins/([a-zA-Z0-9._-]+)/", html)))
        themes = sorted(set(re.findall(r"/wp-content/themes/([a-zA-Z0-9._-]+)/", html)))
        if plugins:
            fp["plugins"] = plugins
            kv("Plugins", ", ".join(plugins))
        if themes:
            fp["themes"] = themes
            kv("Themes", ", ".join(themes))
        if not fp.get("wp_version"):
            gen = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', html)
            if gen:
                fp["wp_version"] = gen.group(1)
                ok("WordPress %s (generator meta tag)" % gen.group(1))
    except Exception:
        pass

    state.fingerprint = fp
    return fp


def module_enum_users(client: RPCClient, state: "State", limit: int = 20) -> List[str]:
    """Find valid usernames via three independent WordPress leaks."""
    head("User enumeration")
    found: List[str] = []

    # 1. REST API leak. WordPress 4.7+ exposes the users collection, but the
    #    path depends on permalink settings: pretty permalinks give
    #    /wp-json/wp/v2/users, plain permalinks give /?rest_route=/wp/v2/users.
    base = client.url.rsplit("/", 1)[0] + "/"
    rest_candidates = [
        urllib.parse.urljoin(base, "wp-json/wp/v2/users?per_page=100"),
        "%s?rest_route=/wp/v2/users&per_page=100" % base,
    ]
    for rest_url in rest_candidates:
        try:
            req = urllib.request.Request(
                rest_url,
                headers={"User-Agent": client.user_agent, "Accept": "application/json"},
            )
            with client._opener.open(req, timeout=client.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            continue
        if isinstance(data, list) and data:
            ok("REST API leaked %d user(s) at %s" % (len(data), rest_url))
            for u in data:
                slug = u.get("slug") or u.get("name")
                if slug and slug not in found:
                    found.append(slug)
                    kv("user", "%s  (id=%s, name=%s)" % (slug, u.get("id"), u.get("name")))
            break
    else:
        note("REST user collection not reachable (both permalink styles tried).")

    # 2. Author archive. Depending on permalink settings this either 301s to
    #    /author/<slug>/ or serves 200 in place, so the redirect target is not
    #    enough - the body has to be parsed too.
    info("Scanning ?author=1..%d..." % limit)
    for uid in range(1, limit + 1):
        body = ""
        final = ""
        try:
            req = urllib.request.Request(
                "%s?author=%d" % (base, uid),
                headers={"User-Agent": client.user_agent},
            )
            with client._opener.open(req, timeout=client.timeout) as resp:
                final = resp.geturl()
                body = resp.read(120000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            final = getattr(exc, "url", "") or ""
        except Exception:
            continue

        slug = None
        m = re.search(r"/author/([^/?#]+)/?", final)
        if m:
            slug = urllib.parse.unquote(m.group(1))
        if not slug:
            # Served in place. The body class carries both author-<slug> and a
            # numeric author-<id>, so tokenise the class attribute and take the
            # first author-* token that is not purely numeric.
            m = re.search(r'<body[^>]*class="([^"]*)"', body)
            if m:
                for token in m.group(1).split():
                    if token.startswith("author-") and not token[7:].isdigit():
                        slug = token[7:]
                        break
        if not slug:
            # Most reliable: the archive heading's vcard span.
            m = re.search(r'<span class="vcard">([^<]+)</span>', body)
            if m:
                slug = m.group(1).strip()

        if slug and slug not in found and slug.lower() != "author":
            found.append(slug)
            ok("author=%d -> %s" % (uid, slug))

    # 3. Authenticated listing, if we have creds.
    if state.has_creds():
        try:
            if not state.blog_id:
                blogs = client.call_value("wp.getUsersBlogs", state.username, state.password)
                if isinstance(blogs, list) and blogs:
                    state.blog_id = str(blogs[0].get("blogid") or blogs[0].get("blog_id") or "")
            # wp.getUsers requires the filter struct as its 4th argument;
            # omitting it returns fault 400 "Insufficient arguments".
            users = client.call_value(
                "wp.getUsers", state.blog_id, state.username, state.password, {}
            )
            if isinstance(users, list):
                ok("wp.getUsers returned %d account(s)" % len(users))
                for u in users:
                    login = u.get("username") or u.get("user_login") or u.get("nicename")
                    if login and login not in found:
                        found.append(login)
                    kv(str(login), "id=%s role=%s email=%s" % (
                        u.get("user_id"), u.get("roles"), u.get("email", "-")))
        except RPCError as exc:
            note("wp.getUsers failed: %s" % exc)

    if found:
        print()
        ok("%d unique username(s): %s" % (len(found), ", ".join(found)))
    else:
        warn("No usernames recovered. The site is not leaking users through these paths.")

    state.usernames = found
    return found


def module_discover(client: RPCClient, state: "State", verbose: bool = True) -> List[Any]:
    """
    Find where XML-RPC actually lives on this site.

    xmlrpc.php is the default, not the only location. Sites move it, run
    WordPress in a subdirectory, or block the default path while leaving
    another reachable.
    """
    head("Endpoint discovery")
    if wpcompat is None:
        bad("wpcompat.py not found next to xploitrpc.py - discovery unavailable.")
        return []

    info("Probing %d candidate path(s) on %s" % (
        len(wpcompat.DEFAULT_CANDIDATE_PATHS),
        wpcompat._base_of(client.url)))

    results = wpcompat.discover_endpoints(
        client._opener,
        client.url,
        timeout=client.timeout,
        user_agent=client.user_agent,
        verbose=verbose,
    )

    live = [r for r in results if r.live]
    print()
    for r in results:
        if r.live:
            ok("%s  ->  %s" % (r.url, r.detail))
        elif r.kind in (wpcompat.ResponseKind.HTML, wpcompat.ResponseKind.JSON):
            note("%s  ->  HTTP %s %s (%s)" % (r.url, r.status, r.kind, r.detail))
        elif r.kind == "error":
            note("%s  ->  %s" % (r.url, r.detail))

    if live:
        ok("%d live XML-RPC endpoint(s) found." % len(live))
        if live[0].url != client.url:
            warn("The working endpoint is not the one you targeted.")
            note("Re-run against: %s" % live[0].url)
    else:
        bad("No live XML-RPC endpoint among the candidates.")
        note("The site may block XML-RPC entirely, or host it at a custom path.")

    state.report.setdefault("discover", [
        {"url": r.url, "status": r.status, "kind": r.kind, "detail": r.detail, "live": r.live}
        for r in results
    ])
    return results


def module_matrix(client: RPCClient, state: "State", verbose: bool = True) -> List[Any]:
    """
    Check which advertised methods genuinely work.

    Hardened installs advertise the full list from system.listMethods and then
    strip wp.* at the xmlrpc_methods filter. This distinguishes "advertised"
    from "actually callable" without authenticating or changing anything.
    """
    head("Method availability matrix")
    if wpcompat is None:
        bad("wpcompat.py not found next to xploitrpc.py - matrix unavailable.")
        return []

    if not state.methods:
        try:
            state.methods = client.call_value("system.listMethods") or []
        except RPCError as exc:
            bad("Cannot list methods: %s" % exc)
            return []

    info("Probing %d advertised method(s) with no arguments..." % len(state.methods))
    results = wpcompat.probe_method_matrix(
        client, state.methods, verbose=verbose, delay=client.delay
    )

    counts: Dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print()
    for status in (wpcompat.MethodStatus.WORKS, wpcompat.MethodStatus.BAD_ARGS,
                   wpcompat.MethodStatus.NEEDS_AUTH, wpcompat.MethodStatus.FILTERED,
                   wpcompat.MethodStatus.ERROR):
        if status in counts:
            kv(status, counts[status])

    filtered = [r.method for r in results if r.status == wpcompat.MethodStatus.FILTERED]
    if filtered:
        print()
        warn("%d method(s) are advertised but not callable:" % len(filtered))
        for m in filtered[:25]:
            note(m)
        if len(filtered) > 25:
            note("... and %d more" % (len(filtered) - 25))
        warn("A security plugin is filtering methods. Brute force and wp.*")
        warn("modules will fail against this install regardless of credentials.")

    state.report.setdefault("matrix", [
        {"method": r.method, "status": r.status, "fault": r.fault_code, "detail": r.detail}
        for r in results
    ])
    return results


def rest_fetch(client: "RPCClient", base: str, route: str,
               params: str = "") -> Tuple[int, str]:
    """
    Fetch a REST route under either permalink style.

    WordPress exposes REST at /wp-json/<route> with pretty permalinks, or
    /?rest_route=/<route> with plain permalinks. Trying only one silently
    misses every REST finding on half of all installs. Returns the first
    response that is not a bare 404, or the last status/body if all fail.
    """
    candidates = [
        "%swp-json%s%s" % (base, route, ("?" + params) if params else ""),
        "%s?rest_route=%s%s" % (base, route, ("&" + params) if params else ""),
    ]
    last = (0, "")
    for url in candidates:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": client.user_agent, "Accept": "application/json"},
        )
        try:
            with client._opener.open(req, timeout=client.timeout) as resp:
                result = (getattr(resp, "status", resp.getcode()),
                          resp.read(200000).decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            try:
                result = (exc.code, exc.read(200000).decode("utf-8", errors="replace"))
            except Exception:
                result = (exc.code, "")
        except Exception:
            result = (0, "")
        if result[0] != 404:
            return result
        last = result
    return last


def module_restcheck(client: RPCClient, state: "State") -> Dict[str, Any]:
    """
    Assess REST API hardening: what the REST surface reveals without auth.

    XML-RPC and the REST API are sibling attack surfaces; a site that hardens
    one and not the other is common, and the REST side often leaks more.
    """
    head("REST API hardening check")
    base = client.url.rsplit("/", 1)[0] + "/"
    out: Dict[str, Any] = {}

    def fetch(route: str, params: str = "") -> Tuple[int, str]:
        return rest_fetch(client, base, route, params)

    # 1. Root index: which namespaces are served.
    status, body = fetch("/")
    if status == 200 and body.strip().startswith("{"):
        out["index"] = True
        ok("REST index is served (pretty or plain permalinks).")
        try:
            idx = json.loads(body)
            routes = sorted(idx.get("routes", {}).keys())
            # Routes are absolute paths like "/wp/v2/posts", so the namespace
            # is the first non-empty segment.
            roots = set()
            for route in routes:
                parts = [p for p in route.split("/") if p]
                if parts:
                    roots.add(parts[0])
            roots = sorted(roots)
            kv("namespaces", ", ".join(roots[:12]) or "(none)")
            out["namespaces"] = roots
        except Exception:
            note("Index present but not parseable as JSON.")
    else:
        out["index"] = False
        note("REST index not served (HTTP %s)." % (status or "n/a"))

    # 2. User enumeration via REST, with and without context=edit.
    for label, route, params in (
        ("plain", "/wp/v2/users", "per_page=100"),
        ("context=edit", "/wp/v2/users", "context=edit"),
    ):
        status, body = fetch(route, params)
        leaked = False
        if status == 200 and body.strip().startswith("["):
            try:
                data = json.loads(body)
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    first = data[0]
                    if "email" in first or "roles" in first:
                        ok("%s: users endpoint leaks email/roles (%d user(s))"
                           % (label, len(data)))
                        state.add_finding("high",
                                          "REST users endpoint leaks sensitive fields",
                                          "context=edit is served to unauthenticated "
                                          "visitors, exposing email addresses and roles.",
                                          route + "?" + params)
                    else:
                        ok("%s: users endpoint leaks %d user(s)"
                           % (label, len(data)))
                    leaked = True
                    out.setdefault("users", []).extend(
                        u.get("slug") or u.get("name") for u in data
                        if isinstance(u, dict))
            except Exception:
                pass
        if not leaked:
            note("%s: users endpoint not leaking (HTTP %s)." % (label, status or "n/a"))

    # 3. Application passwords endpoint.
    status, body = fetch("/wp/v2/users/1/application-passwords")
    if status in (401, 403):
        out["app_passwords"] = "endpoint-exists-auth-gated"
        note("Application passwords endpoint exists but is auth-gated (HTTP %d)." % status)
    elif status == 200:
        out["app_passwords"] = "reachable-unauthenticated"
        bad("Application passwords endpoint answered WITHOUT authentication!")
        state.add_finding("critical", "Application passwords endpoint is unauthenticated",
                          "The application-passwords REST endpoint answered without "
                          "credentials. This is not standard WordPress behaviour and "
                          "may expose credential material.",
                          "wp-json/wp/v2/users/1/application-passwords")
    else:
        out["app_passwords"] = "absent"
        note("Application passwords endpoint not present (HTTP %s)." % (status or "n/a"))

    return out


def module_osint(client: RPCClient, state: "State") -> Dict[str, Any]:
    """
    Harvest public WordPress content for credential clues.

    Reads posts, comments and user profiles through the public REST API (no
    auth, no state change) and prints any sentence containing a clue keyword.
    This is what turns a hint like "iloveyou, Mom" into a wordlist entry.
    """
    head("OSINT / clue mining (public content)")
    base = client.url.rsplit("/", 1)[0] + "/"
    out: Dict[str, Any] = {"clues": [], "candidates": []}

    def get_json(route: str, params: str = "per_page=100") -> Any:
        status, body = rest_fetch(client, base, route, params)
        if status == 200:
            try:
                return json.loads(body)
            except Exception:
                return None
        return None

    def sentences(text: str) -> List[str]:
        text = html.unescape(re.sub(r"<[^>]+>", " ", text or ""))
        parts = re.split(r"(?<=[.!?])\s+|<br\s*/?>|\n+", text)
        return [re.sub(r"\s+", " ", p).strip() for p in parts if p.strip()]

    corpus: List[Tuple[str, str]] = []  # (source, text)
    for route, label, key in (
        ("/wp/v2/posts", "post", "content"),
        ("/wp/v2/comments", "comment", "content"),
        ("/wp/v2/pages", "page", "content"),
    ):
        data = get_json(route)
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                rendered = item.get(key, {})
                body = rendered.get("rendered", "") if isinstance(rendered, dict) else str(rendered)
                title = item.get("title", {})
                title_s = title.get("rendered", "") if isinstance(title, dict) else ""
                corpus.append((label, (title_s or "") + " " + body))

    users = get_json("/wp/v2/users")
    if isinstance(users, list):
        for u in users:
            if isinstance(u, dict):
                corpus.append(("user", " ".join(str(u.get(k, "")) for k in
                                                ("name", "slug", "description"))))

    for source, text in corpus:
        for sent in sentences(text):
            low = sent.lower()
            if any(kw in low for kw in CLUE_KEYWORDS):
                out["clues"].append({"source": source, "text": sent})
                ok("[%s] %s" % (source, sent[:160]))

    # Derive candidate passwords from clue sentences: the last word before a
    # comma/signoff is often the intended password ("iloveyou, Mom").
    for clue in out["clues"]:
        text = clue["text"]
        for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9_!@]{3,})\s*,", text):
            out["candidates"].append(m.group(1))
        for m in re.finditer(r"\b(iloveyou|loveyou|ilovemom|password|secret)\b", text, re.I):
            out["candidates"].append(m.group(1).lower())

    out["candidates"] = list(dict.fromkeys(out["candidates"]))
    if out["candidates"]:
        print()
        kv("derived candidates", ", ".join(out["candidates"][:20]))
        note("Feed these into brute with --passlist, or use --derive on brute.")
    else:
        note("No obvious password clues found in public content.")

    state.report.setdefault("osint", out)
    return out


def module_scan(client: RPCClient, state: "State", args: argparse.Namespace) -> Dict[str, Any]:
    """Everything that does not need credentials, in one pass."""
    head("Full unauthenticated scan")
    report: Dict[str, Any] = {"url": client.url, "timestamp": datetime.now(timezone.utc).isoformat()}

    report["probe"] = module_probe(client, state)
    if not report["probe"].get("xmlrpc"):
        warn("Endpoint is not speaking XML-RPC - stopping.")
        return report

    report["fingerprint"] = module_fingerprint(client, state)
    report["methods"] = module_list_methods(client, state)
    report["users"] = module_enum_users(
        client, state, limit=getattr(args, "author_scan", 20) or 20
    )

    if getattr(args, "matrix", False):
        module_matrix(client, state, verbose=False)

    if state.has_creds():
        report["dump"] = module_dump(client, state)

    state.report = report
    return report


