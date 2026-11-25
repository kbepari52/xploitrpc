"""xrpc.cve - extracted from the original xploitrpc monolith."""
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
from .payloads import CROP_VULNERABLE_MAX
from .cve_data import WPCVE_DB
from .recon import module_fingerprint

def crop_target_vulnerable(wp_version: Optional[str]) -> Tuple[bool, str]:
    """Return (probably_vulnerable, reason) for a WordPress version string."""
    if not wp_version:
        return False, "WordPress version unknown - cannot assess CVE-2019-8942."
    vt = version_tuple(wp_version)
    if vt[:2] == (4, 9) and vt >= (4, 9, 0) and vt <= (4, 9, 10):
        return True, "WordPress 4.9.x is in the affected range (<= 4.9.8 per advisory)."
    if vt[:2] == (5, 0) and vt <= CROP_VULNERABLE_MAX:
        return True, "WordPress %s is in the affected range (<= 5.0.3)." % wp_version
    if vt > CROP_VULNERABLE_MAX:
        return False, "WordPress %s is newer than the affected range." % wp_version
    return False, "WordPress %s is outside the known affected range." % wp_version


def _version_vulnerable(vt: Tuple[int, ...], rec: Dict[str, Any]):
    """
    Branch-aware vulnerability check.

    Returns True (confirmed in range), False (not affected), or the string
    "ambiguous" (branch has no known fix floor - do NOT claim exploitation).
    """
    introduced = rec.get("introduced")
    if introduced and vt < introduced:
        return False

    branch = vt[:2]
    fixes = rec.get("branch_fixes") or {}
    if branch in fixes:
        return vt < fixes[branch]

    mainline = rec.get("mainline_fix")
    if mainline and branch > mainline[:2]:
        return False  # a later branch than the mainline fix includes the fix

    # Older/unlisted branch. WordPress backports to supported branches, but
    # without an exact floor we cannot claim a hit.
    return "ambiguous"


def assess_version_cves(wp_version: Optional[str],
                        xmlrpc_only: bool = False) -> List[Dict[str, Any]]:
    """Return CVE records whose affected range contains wp_version, with confidence."""
    if not wp_version:
        return []
    vt = version_tuple(wp_version)
    if vt == (0,):
        return []
    out = []
    for rec in WPCVE_DB:
        if xmlrpc_only and not rec["xmlrpc"]:
            continue
        verdict = _version_vulnerable(vt, rec)
        if verdict is False:
            continue
        item = dict(rec)
        item["confidence"] = "confirmed" if verdict is True else "ambiguous"
        out.append(item)
    return out


def module_cves(client: RPCClient, state: "State",
                version: Optional[str] = None,
                show_all: bool = False,
                xmlrpc_only: bool = False) -> Dict[str, Any]:
    """
    Map a WordPress version (auto-detected or supplied) to known RCE and
    exploitation CVEs, and state plainly which ones the toolkit can exercise.
    """
    head("WordPress version -> RCE / XML-RPC exploit map")

    if show_all:
        note("Full knowledge base (%d records). Source URLs are advisory records."
             % len(WPCVE_DB))
        for rec in WPCVE_DB:
            fixes = ", ".join(
                "%s.%s fixed in %s" % (b[0], b[1], ".".join(map(str, f)))
                for b, f in sorted(rec.get("branch_fixes", {}).items())
            ) or "per-branch floors not encoded"
            print()
            print("  %s  [%s | %s]" % (rec["cve"], rec["impact"], rec["auth"]))
            print("    %s" % rec["title"])
            print("    fix floors: %s" % fixes)
            print("    xml-rpc: %s | tool: %s" % (
                "yes" if rec["xmlrpc"] else "no", rec["tool_module"] or "assessment only"))
            print("    source: %s" % rec["source"])
        return {"all": True, "count": len(WPCVE_DB)}

    ver = version or state.fingerprint.get("wp_version") or ""
    if not ver:
        info("No version known yet; fingerprinting the target...")
        try:
            module_fingerprint(client, state)
        except Exception:
            pass
        ver = state.fingerprint.get("wp_version") or ""
    if not ver:
        bad("Could not determine the WordPress version. Pass --version X.Y.Z.")
        return {"error": "unknown version"}

    ok("Assessing WordPress %s%s" % (ver, " (XML-RPC vectors only)" if xmlrpc_only else ""))
    matches = assess_version_cves(ver, xmlrpc_only=xmlrpc_only)
    out: Dict[str, Any] = {"version": ver, "xmlrpc_only": xmlrpc_only, "matches": []}

    if not matches:
        note("No CVEs in this knowledge base match version %s." % ver)
        note("This is not proof of safety: plugin/theme CVEs are out of scope here.")
    else:
        for rec in matches:
            confirmed = rec["confidence"] == "confirmed"
            has_module = bool(rec["tool_module"])
            probe_only = has_module and "probe only" in rec["tool_module"]
            if not confirmed:
                tag = "backport uncertain - verify"
            elif probe_only:
                tag = "probe only"
            elif has_module:
                tag = "EXPLOIT MODULE"
            else:
                tag = "assessment only"
            out["matches"].append({
                "cve": rec["cve"], "impact": rec["impact"], "auth": rec["auth"],
                "tool_module": rec["tool_module"], "source": rec["source"],
                "confidence": rec["confidence"], "tag": tag,
            })
            print()
            print("  %s  [%s]  %s" % (rec["cve"], rec["impact"], tag))
            print("    %s" % rec["title"])
            print("    auth required: %s | xml-rpc: %s" % (
                rec["auth"], "yes" if rec["xmlrpc"] else "no"))
            if rec["tool_module"]:
                print("    tool module: %s" % rec["tool_module"])
            if rec.get("note"):
                print("    note: %s" % rec["note"])
            print("    source: %s" % rec["source"])
            if confirmed and has_module and not probe_only:
                state.add_finding(
                    "critical" if rec["impact"] == "RCE" else "high",
                    "Version-matched exploit available: %s" % rec["cve"],
                    "WordPress %s is in the affected range for %s (%s). The toolkit "
                    "has a module for this: %s." % (
                        ver, rec["cve"], rec["impact"], rec["tool_module"]),
                    rec["source"],
                )

    print()
    note("Version matching is branch-aware and advisory-based, but cannot see a "
         "target's actual patch state. Entries marked 'backport uncertain' need "
         "manual verification. Plugin/theme CVEs are not covered.")
    state.report.setdefault("cves", out)
    return out


