"""xrpc.cli - extracted from the original xploitrpc monolith."""
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

from .auth import (module_brute, _read_wordlist, derive_candidates)
from .audit import module_audit
from .cve import module_cves
from .data import module_call, module_dump
from .offense import (module_exploit_crop, module_exploit_upload, module_xmlattack,
                      module_multicall_amplify, module_pingback, module_postauth)
from .recon import (module_probe, module_list_methods, module_fingerprint,
                    module_enum_users, module_discover, module_matrix, module_restcheck,
                    module_osint, module_scan)
MENU = """
  {t}XML-RPC toolkit{t}
  {d}--------------------------------------------------{d}
   1. Probe endpoint (reachability, stack, capabilities)
   2. List methods
   3. Fingerprint (version, plugins, options)
   4. Enumerate users
   5. Credential testing (brute / multicall)
   6. Multicall amplification test
   7. Pingback SSRF test
   8. Authenticated dump
   9. Call any method
  10. Full scan
  11. Set / change credentials
  12. Save report
  13. Discover endpoint (try common paths)
  14. Method availability matrix
  15. Security audit (read-only, findings report)
  16. REST API hardening check
  17. Post-auth actions (upload / options - GATED)
  18. Exploit: crop-image RCE CVE-2019-8942 (GATED)
  19. XML parser attacks: XXE / entity expansion (GATED)
  20. Version -> RCE / XML-RPC CVE map
   0. Exit
"""


def interactive(client: RPCClient, state: State) -> None:
    while True:
        print(MENU.format(t=Term.paint("", "bold"), d=Term.paint("", "grey")))
        if state.has_creds():
            note("session: %s:%s  blog_id=%s" % (
                state.username, "*" * len(state.password or ""), state.blog_id or "?"))
        else:
            note("session: unauthenticated")

        try:
            raw = input(Term.paint("  select> ", "cyan", "bold")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not raw:
            continue
        if not raw.isdigit():
            bad("Enter a number.")
            continue

        choice = int(raw)
        try:
            if choice == 0:
                return
            elif choice == 1:
                module_probe(client, state)
            elif choice == 2:
                pat = input("  filter regex (blank for all): ").strip() or None
                module_list_methods(client, state, pat)
            elif choice == 3:
                module_fingerprint(client, state)
            elif choice == 4:
                lim = input("  scan author ids 1..N [20]: ").strip()
                module_enum_users(client, state, int(lim) if lim.isdigit() else 20)
            elif choice == 5:
                _interactive_brute(client, state)
            elif choice == 6:
                m = input("  method to stack [system.listMethods]: ").strip() or "system.listMethods"
                n = input("  batch size [250]: ").strip()
                module_multicall_amplify(client, state, m, int(n) if n.isdigit() else 250)
            elif choice == 7:
                t = input("  target post URL (blank = site root): ").strip() or client.url.rsplit("/", 1)[0] + "/"
                s = input("  source URL (blank = auto callback): ").strip() or None
                module_pingback(client, state, t, s)
            elif choice == 8:
                module_dump(client, state)
            elif choice == 9:
                _interactive_call(client, state)
            elif choice == 10:
                ns = argparse.Namespace(author_scan=20)
                module_scan(client, state, ns)
            elif choice == 11:
                _interactive_creds(state)
            elif choice == 12:
                path = input("  output path [report.json]: ").strip() or "report.json"
                write_report(state, path, "md" if path.endswith(".md") else "json")
            elif choice == 13:
                module_discover(client, state)
            elif choice == 14:
                module_matrix(client, state)
            elif choice == 15:
                module_audit(client, state, argparse.Namespace(author_scan=20))
            elif choice == 16:
                module_restcheck(client, state)
            elif choice == 17:
                _interactive_postauth(client, state)
            elif choice == 18:
                _interactive_exploit(client, state)
            elif choice == 19:
                module_xmlattack(client, state, confirmed=False)
            elif choice == 20:
                module_cves(client, state)
            else:
                bad("No such option.")
        except KeyboardInterrupt:
            print()
            warn("Interrupted - back to menu.")
        except RPCError as exc:
            bad(str(exc))
        except Exception as exc:
            bad("%s: %s" % (type(exc).__name__, exc))


def _interactive_creds(state: State) -> None:
    head("Credentials")
    u = input("  username: ").strip()
    p = input("  password: ").strip()
    b = input("  blog_id (blank = auto-resolve): ").strip()
    if u and p:
        state.username, state.password = u, p
        state.blog_id = b or None
        ok("Session credentials set.")


def _interactive_brute(client: RPCClient, state: State) -> None:
    head("Credential testing")
    u = input("  username (blank = use a file): ").strip()
    if u:
        users = [u]
    else:
        path = input("  username file: ").strip()
        users = _read_wordlist(path)
        ok("%d username(s) loaded" % len(users))

    path = input("  password file: ").strip()
    passwords = _read_wordlist(path)
    ok("%d password(s) loaded" % len(passwords))

    mode = input("  use multicall batching? (fast but unreliable) [y/N]: ").strip().lower()
    batch = "50"
    if mode == "y":
        batch = input("  multicall batch size [50]: ").strip() or "50"
    module_brute(
        client, state, users, passwords,
        batch_size=int(batch) if batch.isdigit() else 50,
        use_multicall=(mode == "y"),
    )


def _interactive_exploit(client: RPCClient, state: State) -> None:
    head("Exploit modules (STATE-CHANGING, GATED)")
    print("  1. Crop-image RCE (CVE-2019-8942 / 8943)")
    choice = input("  select> ").strip()
    if choice == "1":
        cmd = input("  command to run via webshell [id]: ").strip() or "id"
        theme = input("  theme dir (blank = auto-detect): ").strip() or None
        module_exploit_crop(client, state, cmd=cmd, confirmed=False, theme=theme)
    else:
        note("Nothing selected.")


def _interactive_postauth(client: RPCClient, state: State) -> None:
    head("Post-auth actions (STATE-CHANGING)")
    print("  1. Upload a file (wp.uploadFile)")
    print("  2. Set an option (wp.setOptions)")
    choice = input("  select> ").strip()
    if choice == "1":
        path = input("  local file path: ").strip()
        remote = input("  remote filename (blank = same): ").strip() or None
        module_postauth(client, state, upload=path or None,
                        remote_name=remote, confirmed=False)
    elif choice == "2":
        name = input("  option name: ").strip()
        value = input("  new value: ").strip()
        if name and value:
            module_postauth(client, state, set_option=(name, value), confirmed=False)
    else:
        note("Nothing selected.")


def _interactive_call(client: RPCClient, state: State) -> None:
    head("Call any method")
    if state.methods:
        note("known methods: %d (see option 2)" % len(state.methods))
    method = input("  method name: ").strip()
    if not method:
        return
    raw = input("  arguments, space separated (str:/int:/json:/file: prefixes): ").strip()
    args = raw.split() if raw else []
    module_call(client, state, method, args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xploitrpc",
        description="WordPress XML-RPC attack surface toolkit. Authorized testing only.",
        epilog="Example: python xploitrpc.py -u http://target/xmlrpc.php scan",
    )
    p.add_argument("-u", "--url", help="XML-RPC endpoint (bare host gets /xmlrpc.php appended)")
    p.add_argument("--user", help="username for authenticated modules")
    p.add_argument("--password", help="password for authenticated modules")
    p.add_argument("--blog-id", help="WordPress blog id (auto-resolved when omitted)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-request timeout, seconds")
    p.add_argument("--delay", type=float, default=0.0, help="delay between requests, seconds")
    p.add_argument("--retries", type=int, default=1, help="transport retries on failure")
    p.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent header")
    p.add_argument("-v", "--verbose", action="store_true", help="per-request diagnostics")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("--no-banner", action="store_true", help="suppress the banner")
    p.add_argument("-o", "--output", help="write a report to this path (.json or .md)")
    p.add_argument("--version", action="version", version="xploitrpc %s" % __version__)

    sub = p.add_subparsers(dest="command")

    sub.add_parser("menu", help="interactive menu (default when no command given)")
    sub.add_parser("probe", help="reachability and capability probe")

    lp = sub.add_parser("list", help="list XML-RPC methods")
    lp.add_argument("--filter", help="regex filter")

    sub.add_parser("fingerprint", help="version, plugins, options")

    up = sub.add_parser("users", help="enumerate usernames")
    up.add_argument("--author-scan", type=int, default=20, help="how many ?author=N ids to try")

    bp = sub.add_parser("brute", help="credential testing")
    bp.add_argument("--userlist", help="file of usernames")
    bp.add_argument("--passlist", help="file of passwords")
    bp.add_argument("--derive", action="store_true",
                    help="generate password candidates automatically from usernames, "
                         "common passwords and mined site clues (no wordlist needed)")
    bp.add_argument("--osint", action="store_true",
                    help="mine public posts/comments for password clues first, then derive")
    bp.add_argument("--batch", type=int, default=50, help="multicall batch size")
    bp.add_argument("--multicall", action="store_true",
                    help="batch attempts via system.multicall (FAST but UNRELIABLE: "
                         "WordPress poisons the batch after the first failed login)")
    bp.add_argument("--threads", type=int, default=1, help="workers for single-request mode")
    bp.add_argument("--keep-going", action="store_true", help="do not stop at the first hit")

    mp = sub.add_parser("multicall", help="multicall amplification test")
    mp.add_argument("--method", default="system.listMethods")
    mp.add_argument("--count", type=int, default=250)

    pp = sub.add_parser("pingback", help="pingback.ping SSRF test")
    pp.add_argument("--target", required=True, help="a post URL on the target site")
    pp.add_argument("--source", help="URL the server should fetch (your callback)")

    xp = sub.add_parser("xmlattack", help="XML parser attacks: XXE, entity expansion, malformed XML (GATED)")
    xp.add_argument("--confirmed", action="store_true",
                    help="acknowledge authorised parser testing (typed confirmation also required)")

    cv = sub.add_parser("cves", help="map WordPress version to known RCE / XML-RPC CVEs")
    cv.add_argument("--version", help="assess this version instead of auto-detecting")
    cv.add_argument("--all", dest="show_all", action="store_true",
                    help="print the whole knowledge base with sources")
    cv.add_argument("--xmlrpc-only", action="store_true",
                    help="only show CVEs reachable through XML-RPC")

    cp = sub.add_parser("call", help="invoke one method")
    cp.add_argument("method")
    cp.add_argument("args", nargs="*", help="typed args: str:x int:5 json:{...} file:path")

    dp = sub.add_parser("dump", help="authenticated data dump")
    dp.add_argument("--posts", type=int, default=5)

    sp = sub.add_parser("scan", help="full unauthenticated scan")
    sp.add_argument("--author-scan", type=int, default=20, help="how many ?author=N ids to try")
    sp.add_argument("--matrix", action="store_true",
                    help="also check which advertised methods actually work")

    ap = sub.add_parser("audit", help="full read-only security audit with findings report")
    ap.add_argument("--author-scan", type=int, default=20, help="how many ?author=N ids to try")

    sub.add_parser("restcheck", help="REST API hardening check (read-only)")

    sub.add_parser("osint", help="mine public posts/comments for credential clues")

    ex = sub.add_parser("exploit", help="CVE exploit modules (GATED, authorised use only)")
    ex.add_argument("name", choices=["crop", "upload"],
                    help="exploit module (crop = CVE-2019-8942/8943, "
                         "upload = wp.uploadFile template include)")
    ex.add_argument("--cmd", default="id", help="command for the webshell to execute (default: id)")
    ex.add_argument("--theme", help="active theme directory (auto-detected if omitted)")
    ex.add_argument("--shell-file", help="custom PHP shell file for the upload exploit")
    ex.add_argument("--confirmed", action="store_true",
                    help="acknowledge this is an authorised exploit test "
                         "(a typed confirmation is also required)")

    pa = sub.add_parser("postauth", help="authenticated state-changing actions (GATED)")
    pa.add_argument("--upload", help="file to upload via wp.uploadFile")
    pa.add_argument("--as", dest="remote_name", help="remote filename for the upload")
    pa.add_argument("--set-option", nargs=2, metavar=("NAME", "VALUE"),
                    help="set a WordPress option via wp.setOptions")
    pa.add_argument("--confirmed", action="store_true",
                    help="acknowledge this is an authorised state-changing test "
                         "(a typed confirmation is also required)")

    sub.add_parser("discover", help="find the XML-RPC endpoint (tries common paths)")

    mx = sub.add_parser("matrix", help="check which advertised methods actually work")
    mx.add_argument("--quiet", action="store_true", help="summary only")

    return p


def _reparse_globals(parser: argparse.ArgumentParser, args: argparse.Namespace,
                     argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """
    Let global flags appear before or after the subcommand.

    argparse only accepts main-parser flags ahead of the subcommand, so
    `scan -o report.json` would fail. Move any recognised global flag to the
    front and parse again.
    """
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)

    # Flags that consume the following token as their value.
    takes_value = {
        "-u", "--url", "--user", "--password", "--blog-id", "--timeout",
        "--delay", "--retries", "--proxy", "--user-agent", "-o", "--output",
    }
    boolean = {
        "--insecure", "-v", "--verbose", "--no-color", "--no-banner", "--version",
        "-h", "--help",
    }

    globals_part: List[str] = []
    rest: List[str] = []
    i = 0
    seen_command = False
    while i < len(argv):
        tok = argv[i]
        if tok in takes_value:
            globals_part.append(tok)
            if i + 1 < len(argv):
                globals_part.append(argv[i + 1])
                i += 2
                continue
            i += 1
            continue
        if tok in boolean:
            globals_part.append(tok)
            i += 1
            continue
        # --flag=value form
        if tok.startswith("--") and "=" in tok and tok.split("=", 1)[0] in takes_value:
            globals_part.append(tok)
            i += 1
            continue
        if not seen_command and not tok.startswith("-"):
            seen_command = True
        rest.append(tok)
        i += 1

    if not globals_part:
        return args
    try:
        return parser.parse_args(globals_part + rest)
    except SystemExit:
        return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    Term.enable_windows_vt()
    parser = build_parser()
    # parse_known_args so that global flags placed after the subcommand do not
    # abort the run before _reparse_globals gets a chance to move them.
    args, _unknown = parser.parse_known_args(argv)
    args = _reparse_globals(parser, args, argv)

    if args.no_color:
        Term.enabled = False

    if not args.no_banner:
        print_banner()

    # No URL and no command: ask, then drop into the menu.
    url = args.url
    if not url:
        try:
            url = input(Term.paint("  target> ", "cyan", "bold")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
    if not url:
        parser.print_help()
        return 1

    try:
        client = RPCClient(
            url,
            timeout=args.timeout,
            user_agent=args.user_agent,
            insecure=args.insecure,
            proxy=args.proxy,
            verbose=args.verbose,
            delay=args.delay,
            retries=args.retries,
        )
    except ValueError as exc:
        die("bad URL: %s" % exc)

    state = State(url=client.url, username=args.user, password=args.password,
                  blog_id=args.blog_id)

    info("Target: %s" % client.url)

    cmd = args.command or "menu"

    try:
        if cmd == "menu":
            interactive(client, state)
        elif cmd == "probe":
            module_probe(client, state)
        elif cmd == "list":
            module_list_methods(client, state, getattr(args, "filter", None))
        elif cmd == "fingerprint":
            module_fingerprint(client, state)
        elif cmd == "users":
            module_enum_users(client, state, args.author_scan)
        elif cmd == "brute":
            users = [args.user] if args.user else []
            if args.userlist:
                users = _read_wordlist(args.userlist)
            if not users:
                die("brute needs --user or --userlist")
            if not args.passlist and not args.derive:
                die("brute needs --passlist, or use --derive to generate candidates")
            if args.derive:
                clues: List[str] = []
                if args.osint:
                    osint_out = module_osint(client, state)
                    clues = osint_out.get("candidates", [])
                passwords = derive_candidates(users, clues)
                info("Derived %d candidate password(s) from usernames%s." % (
                    len(passwords), " + site clues" if clues else ""))
            else:
                passwords = _read_wordlist(args.passlist)
            module_brute(
                client, state, users, passwords,
                batch_size=args.batch,
                use_multicall=args.multicall,
                stop_on_first=not args.keep_going,
                threads=args.threads,
            )
        elif cmd == "multicall":
            module_multicall_amplify(client, state, args.method, args.count)
        elif cmd == "pingback":
            module_pingback(client, state, args.target, args.source)
        elif cmd == "xmlattack":
            module_xmlattack(client, state, confirmed=args.confirmed)
        elif cmd == "cves":
            module_cves(client, state, version=getattr(args, "version", None),
                        show_all=getattr(args, "show_all", False),
                        xmlrpc_only=getattr(args, "xmlrpc_only", False))
        elif cmd == "call":
            module_call(client, state, args.method, args.args)
        elif cmd == "dump":
            module_dump(client, state, args.posts)
        elif cmd == "scan":
            module_scan(client, state, args)
        elif cmd == "audit":
            module_audit(client, state, args)
        elif cmd == "restcheck":
            module_restcheck(client, state)
        elif cmd == "osint":
            module_osint(client, state)
        elif cmd == "exploit":
            if args.name == "crop":
                module_exploit_crop(client, state, cmd=args.cmd,
                                    confirmed=args.confirmed, theme=args.theme)
            elif args.name == "upload":
                module_exploit_upload(client, state, cmd=args.cmd,
                                      confirmed=args.confirmed,
                                      shell_path=getattr(args, "shell_file", None))
        elif cmd == "postauth":
            set_opt = tuple(args.set_option) if args.set_option else None
            module_postauth(client, state, upload=args.upload,
                            remote_name=args.remote_name,
                            set_option=set_opt, confirmed=args.confirmed)
        elif cmd == "discover":
            module_discover(client, state)
        elif cmd == "matrix":
            module_matrix(client, state, verbose=not args.quiet)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
        return 130
    except RPCError as exc:
        bad(str(exc))
        return 1

    if args.output:
        write_report(state, args.output, "md" if args.output.endswith(".md") else "json")

    return 0


