"""xrpc.data - extracted from the original xploitrpc monolith."""
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

def parse_arg(token: str) -> Any:
    """
    Typed argument parsing for the `call` command.

    Bare tokens stay STRINGS. This is deliberate and is the fix for the original
    tool's silent int coercion, where a password of 123456 became the integer
    123456 and WordPress rejected it. Type conversion only happens when the
    caller asks for it with an explicit prefix:

        str:hello      -> "hello"
        int:42         -> 42
        float:1.5      -> 1.5
        bool:true      -> True
        json:{"a": 1}  -> {"a": 1}
        file:./img.png -> <binary>
        b64:iVBORw...  -> <binary>
    """
    token = token.strip()
    if ":" in token:
        kind, _, rest = token.partition(":")
        kind_l = kind.lower()
        if kind_l == "str":
            return rest
        if kind_l == "int":
            return int(rest)
        if kind_l == "float":
            return float(rest)
        if kind_l == "bool":
            return rest.lower() in ("1", "true", "yes", "on")
        if kind_l == "json":
            return json.loads(rest)
        if kind_l == "file":
            with open(rest, "rb") as fh:
                return xmlrpc.client.Binary(fh.read())
        if kind_l == "b64":
            return xmlrpc.client.Binary(base64.b64decode(rest))
    # No recognised prefix: the token is a string, always.
    return token


def module_call(client: RPCClient, state: "State", method: str,
                args: Sequence[str]) -> Any:
    head("Call: %s" % method)
    parsed: List[Any] = []
    for i, raw in enumerate(args, 1):
        try:
            val = parse_arg(raw)
        except Exception as exc:
            bad("arg %d (%r) could not be parsed: %s" % (i, raw, exc))
            note("Use a prefix: str: int: float: bool: json: file: b64:")
            return None
        parsed.append(val)
        kv("arg %d" % i, "%r  (%s)" % (val, type(val).__name__))

    try:
        res = client.call(method, *parsed)
    except RPCFault as exc:
        bad(describe_fault(exc))
        return None
    except RPCError as exc:
        bad(str(exc))
        return None

    ok("HTTP %d in %.3fs, %d bytes" % (res.status, res.elapsed, res.bytes_in))
    print()
    print(json.dumps(_jsonable(res.value), indent=2, ensure_ascii=False, default=str))
    return res.value


def _jsonable(value: Any) -> Any:
    if isinstance(value, xmlrpc.client.Binary):
        return "<binary %d bytes>" % len(value.data)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def module_dump(client: RPCClient, state: "State", post_limit: int = 5) -> Dict[str, Any]:
    """With valid creds, pull the interesting authenticated surface."""
    head("Authenticated data dump")
    if not state.has_creds():
        bad("No credentials. Use --user/--password, or run the brute module first.")
        return {}

    out: Dict[str, Any] = {}

    # Resolve blog_id if we do not have it yet.
    if not state.blog_id:
        try:
            blogs = client.call_value("wp.getUsersBlogs", state.username, state.password)
            if isinstance(blogs, list) and blogs:
                state.blog_id = str(blogs[0].get("blogid") or blogs[0].get("blog_id") or "")
                ok("Resolved blog_id=%s" % state.blog_id)
                out["blogs"] = _jsonable(blogs)
        except RPCError as exc:
            bad("Cannot resolve blog_id: %s" % exc)
            return out

    tasks = [
        ("profile", "wp.getProfile", (state.blog_id, state.username, state.password)),
        ("users", "wp.getUsers", (state.blog_id, state.username, state.password)),
        ("options", "wp.getOptions", (state.blog_id, state.username, state.password)),
        ("posts", "wp.getPosts", (state.blog_id, state.username, state.password,
                                  {"number": post_limit})),
        ("categories", "wp.getCategories", (state.blog_id, state.username, state.password)),
        ("comments", "wp.getComments", (state.blog_id, state.username, state.password,
                                        {"number": 10})),
    ]

    for label, method, params in tasks:
        try:
            val = client.call_value(method, *params)
        except RPCFault as exc:
            note("%s: %s" % (label, describe_fault(exc)))
            continue
        except RPCError as exc:
            note("%s: %s" % (label, exc))
            continue

        out[label] = _jsonable(val)
        if label == "profile" and isinstance(val, dict):
            print()
            ok("Profile")
            for k in ("user_login", "username", "display_name", "email", "roles", "capabilities"):
                if k in val and val[k] not in (None, ""):
                    kv(k, val[k])
        elif label == "users" and isinstance(val, list):
            print()
            ok("%d user account(s)" % len(val))
            for u in val:
                login = u.get("username") or u.get("user_login") or u.get("nicename") or "?"
                kv(str(login), "%s <%s> roles=%s" % (
                    u.get("display_name", "-"), u.get("email", "-"), u.get("roles")))
        elif label == "options" and isinstance(val, dict):
            print()
            ok("%d option(s)" % len(val))
            for k in ("software_version", "blog_title", "blog_url", "users_can_register",
                      "default_role", "blog_public"):
                if k in val:
                    v = val[k].get("value") if isinstance(val[k], dict) else val[k]
                    kv(k, v)
        elif label == "posts" and isinstance(val, list):
            print()
            ok("%d post(s)" % len(val))
            for p in val:
                kv(str(p.get("post_id")), "%s  [%s]" % (p.get("post_title"), p.get("post_status")))
        elif label == "categories" and isinstance(val, list):
            print()
            ok("%d categor(y/ies)" % len(val))
            for cat in val:
                kv(str(cat.get("categoryId")),
                   "%s  (%s)" % (cat.get("categoryName") or cat.get("description"),
                                 cat.get("htmlUrl", "-")))
        elif label == "comments" and isinstance(val, list):
            print()
            ok("%d comment(s)" % len(val))
            for cm in val:
                body = re.sub(r"\s+", " ", str(cm.get("content", "")))[:70]
                kv(str(cm.get("comment_id")),
                   "%s on %r [%s] %s" % (
                       cm.get("author", "-"), cm.get("post_title", "-"),
                       cm.get("status", "-"), body))
        else:
            note("%s: %d record(s)" % (label, len(val) if hasattr(val, "__len__") else 1))

    return out


