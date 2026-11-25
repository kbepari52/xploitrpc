"""xrpc.audit - extracted from the original xploitrpc monolith."""
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
from .recon import (module_probe, module_fingerprint, module_list_methods,
                    module_enum_users, module_restcheck, module_matrix)
from .data import module_dump
from .auth import LockoutDetected

def module_audit(client: RPCClient, state: "State", args: argparse.Namespace) -> Dict[str, Any]:
    """
    Full read-only security audit: everything that observes without mutating,
    chained in one pass, with a severity-rated findings report at the end.

    Deliberately excludes brute force, multicall amplification and pingback
    SSRF: those are active attacks and belong behind explicit commands.
    """
    head("Security audit (read-only)")
    report: Dict[str, Any] = {
        "url": client.url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": [],
    }

    # --- 1. probe: reachability, stack, TLS --------------------------------
    probe = module_probe(client, state)
    report["probe"] = probe
    if not probe.get("xmlrpc"):
        warn("Endpoint is not speaking XML-RPC - audit stops here.")
        state.report = report
        return report

    # TLS findings from the probe stage.
    if client.url.startswith("https://") and getattr(client, "insecure", False):
        state.add_finding("medium", "TLS certificate not verifiable",
                          "The endpoint's certificate failed standard verification "
                          "(incomplete chain, self-signed, or expired). Clients and "
                          "app-password integrations will fail or be MITM-able.",
                          "required --insecure to connect")
    elif client.url.startswith("https://"):
        state.add_finding("info", "TLS certificate verifies cleanly",
                          "Standard certificate validation succeeded.", "")

    # --- 2. version / platform assessment ---------------------------------
    fp = module_fingerprint(client, state)
    report["fingerprint"] = fp

    if wpcompat is not None:
        if fp.get("wp_version"):
            sev, note_text = wpcompat.assess_wp_version(fp["wp_version"])
            if sev != "info":
                state.add_finding(sev, "WordPress core is outdated",
                                  note_text + " XML-RPC behaviour and REST "
                                  "hardening differ significantly from current core.",
                                  "version %s" % fp["wp_version"])
        php = fp.get("php") or probe.get("powered_by") or ""
        sev, note_text = wpcompat.assess_php_version(php)
        if sev != "info":
            state.add_finding(sev, "PHP runtime is end-of-life or aging",
                              note_text + " PHP EOL means no security fixes at "
                              "the language level, independent of WordPress.",
                              php)

    # --- 3. method inventory and namespaces -------------------------------
    methods = state.methods or []
    report["method_count"] = len(methods)
    if len(methods) > 80:
        extra = [m for m in methods if not m.startswith(
            ("system.", "wp.", "blogger.", "metaWeblog.", "mt.", "pingback.", "demo."))]
        if extra and wpcompat is not None:
            ns_map = wpcompat.map_namespaces(methods)
            for ns, guess in ns_map.items():
                state.add_finding("medium", "Plugin extends the XML-RPC API (%s)" % ns,
                                  "Methods in the %s namespace are served by %s. "
                                  "Plugin XML-RPC surfaces are rarely audited as "
                                  "thoroughly as core." % (ns, guess),
                                  "%d method(s): %s" % (len(extra), ", ".join(extra[:5])))

    # --- 4. method matrix: what is actually callable -----------------------
    matrix = module_matrix(client, state, verbose=False)
    report["matrix_summary"] = {}
    for r in matrix:
        report["matrix_summary"][r.status] = report["matrix_summary"].get(r.status, 0) + 1
    filtered = [r.method for r in matrix if r.status == wpcompat.MethodStatus.FILTERED] \
        if wpcompat else []
    if not filtered and len(methods) >= 80:
        state.add_finding("medium", "XML-RPC API is fully open",
                          "Every advertised method is callable (nothing filtered by "
                          "a security plugin). system.multicall is available, so "
                          "credential attacks and amplification are both possible "
                          "if any account is weak.",
                          "%d methods callable" % len(matrix))

    # --- 5. user enumeration ----------------------------------------------
    users = module_enum_users(client, state, limit=getattr(args, "author_scan", 20) or 20)
    report["users"] = users
    if users:
        state.add_finding("high", "Usernames are publicly enumerable",
                          "%d username(s) recovered without authentication. Combined "
                          "with an open XML-RPC endpoint this is the input list for a "
                          "credential attack." % len(users),
                          ", ".join(users))
        if "admin" in users:
            state.add_finding("high", "Default 'admin' username is in use",
                              "The account with the most privileges uses the default "
                              "admin username, which every credential list tries first.",
                              "admin")

    # --- 5b. REST API hardening -------------------------------------------
    report["restcheck"] = module_restcheck(client, state)

    # --- 5c. brute-force protection probe ---------------------------------
    # One deliberately wrong credential tells us whether the site counts
    # attempts and locks out. This is a single request, not an attack.
    if wpcompat is not None and users:
        try:
            client.call_value("wp.getUsersBlogs", users[0], "xploitrpc-lockout-probe")
            state.add_finding("info", "Credential probe accepted a wrong password",
                              "The endpoint returned success for a deliberately wrong "
                              "password, which should be impossible.", users[0])
        except LockoutDetected as exc:
            state.add_finding("info", "Brute-force protection is active",
                              "The site counts failed attempts and reports a lockout "
                              "counter, so credential attacks are rate-limited.",
                              str(exc)[:120])
        except RPCFault:
            state.add_finding("medium", "No brute-force protection detected",
                              "A wrong password returned a plain authentication "
                              "failure with no attempt counter, lockout notice, or "
                              "delay. Combined with an open XML-RPC endpoint and "
                              "enumerable usernames, unlimited guessing is possible.",
                              "single probe, no lockout message")
        except RPCError:
            pass

    # --- 6. authenticated depth (only when creds are supplied) -------------
    if state.has_creds():
        dump = module_dump(client, state)
        report["dump"] = dump
        state.add_finding("info", "Authenticated access confirmed",
                          "Supplied credentials are valid; the dump module shows the "
                          "full authenticated surface.", "")

    # --- 7. print ----------------------------------------------------------
    report["findings"] = state.findings
    print_findings(state.findings)
    state.report = report
    return report


