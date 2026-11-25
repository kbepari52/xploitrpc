"""xrpc.core - shared client, transport, output helpers and state."""
from __future__ import annotations
import argparse, base64, gzip, ipaddress, json, html, itertools, os, random
import re, socket, ssl, string, sys, threading, time
import urllib.error, urllib.parse, urllib.request, xmlrpc.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from .auth import Credential

try:
    from . import wpcompat
except ImportError:  # running a module file directly
    try:
        import wpcompat
    except ImportError:
        wpcompat = None

__version__ = "2.0.0"

DEFAULT_UA = "xploitrpc/%s (+https://github.com/kbepari52)" % __version__


DEFAULT_TIMEOUT = 15.0


BANNER_DELAY = 0.0  # set to 0.06 for the animated banner


class Term:
    """ANSI colour helper with graceful degradation."""

    enabled = True
    _CODES = {
        "red": "31", "green": "32", "yellow": "33", "blue": "34",
        "magenta": "35", "cyan": "36", "white": "37", "grey": "90",
        "bold": "1", "dim": "2",
    }

    @classmethod
    def paint(cls, text: str, *styles: str) -> str:
        if not cls.enabled or not styles:
            return text
        codes = ";".join(cls._CODES[s] for s in styles if s in cls._CODES)
        if not codes:
            return text
        return "\033[%sm%s\033[0m" % (codes, text)

    @classmethod
    def enable_windows_vt(cls) -> None:
        if os.name == "nt":
            try:
                # Enables VT100 processing on modern Windows terminals.
                os.system("")
            except Exception:
                cls.enabled = False


def ok(msg: str) -> None:
    print(Term.paint("[+] ", "green", "bold") + msg)


def bad(msg: str) -> None:
    print(Term.paint("[!] ", "red", "bold") + msg)


def warn(msg: str) -> None:
    print(Term.paint("[~] ", "yellow", "bold") + msg)


def info(msg: str) -> None:
    print(Term.paint("[*] ", "cyan") + msg)


def note(msg: str) -> None:
    print(Term.paint("    " + msg, "grey"))


def head(msg: str) -> None:
    print()
    print(Term.paint(msg, "bold", "white"))
    print(Term.paint("-" * len(msg), "grey"))


def kv(key: str, value: Any, width: int = 26) -> None:
    print("  %s %s" % (Term.paint(key.ljust(width), "grey"), value))


def die(msg: str, code: int = 1) -> None:
    bad(msg)
    sys.exit(code)


class RPCError(Exception):
    """Base class for everything this tool raises."""


class TransportError(RPCError):
    """Network / HTTP level failure. The request never produced a usable XML-RPC reply."""


class ProtocolError(RPCError):
    """The endpoint answered, but not with parseable XML-RPC."""

    def __init__(self, message: str, raw_body: bytes = b"", status: int = 0):
        self.raw_body = raw_body
        self.status = status
        super().__init__(message)


class RPCFault(RPCError):
    """A well-formed XML-RPC fault response from the server."""

    def __init__(self, code: int, message: str, raw: Optional[str] = None):
        self.code = code
        self.message = message
        self.raw = raw
        super().__init__("fault %s: %s" % (code, message))


def normalize_url(raw: str) -> str:
    """Turn whatever the user typed into a usable endpoint URL."""
    url = (raw or "").strip().strip('"').strip("'")
    if not url:
        raise ValueError("empty URL")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parts = urllib.parse.urlsplit(url)
    if not parts.netloc:
        raise ValueError("could not parse a host from %r" % raw)
    path = parts.path or "/"
    # Bare site root: assume the conventional WordPress endpoint.
    if path in ("", "/"):
        path = "/xmlrpc.php"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


@dataclass
class RPCResult:
    """Everything a caller might want to know about one round trip."""
    value: Any
    raw: str
    status: int
    elapsed: float
    bytes_in: int
    headers: Dict[str, str] = field(default_factory=dict)


class RPCClient:
    """
    A thin, controllable XML-RPC client.

    Deliberately not xmlrpc.client.ServerProxy: that class is lazy (so connection
    errors surface at the wrong moment), has no default timeout, and gives no
    access to the HTTP status, headers or raw body. All three matter for a
    pentest tool.
    """

    def __init__(
        self,
        url: str,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_UA,
        insecure: bool = False,
        proxy: Optional[str] = None,
        verbose: bool = False,
        delay: float = 0.0,
        retries: int = 1,
    ) -> None:
        self.url = normalize_url(url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.insecure = insecure
        self.verbose = verbose
        self.delay = max(0.0, delay)
        self.retries = max(0, retries)
        self.request_count = 0
        self._lock = threading.Lock()

        handlers: List[urllib.request.BaseHandler] = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    # -- low level ---------------------------------------------------------

    def post_raw(self, body: bytes, label: str = "request") -> RPCResult:
        """POST a pre-built XML body and return the parsed result."""
        last_err: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(min(2.0 ** attempt, 5.0))
            try:
                return self._post_once(body, label)
            except TransportError as exc:
                last_err = exc
                if self.verbose:
                    warn("transport retry %d/%d: %s" % (attempt + 1, self.retries, exc))
                continue
        raise last_err if last_err else TransportError("request failed")

    def _post_once(self, body: bytes, label: str) -> RPCResult:
        if self.delay:
            time.sleep(self.delay)

        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "Accept": "text/xml",
                "Accept-Encoding": "gzip, identity",
                "User-Agent": self.user_agent,
                "Connection": "close",
            },
        )

        started = time.time()
        status = 0
        headers: Dict[str, str] = {}
        raw_bytes = b""

        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = getattr(resp, "status", resp.getcode())
                headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_bytes = resp.read()
        except urllib.error.HTTPError as exc:
            # WordPress answers 405 for a GET, and some hardened installs answer
            # 403/405 for POST when XML-RPC is disabled. The body still matters.
            status = exc.code
            headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
            try:
                raw_bytes = exc.read()
            except Exception:
                raw_bytes = b""
        except socket.timeout:
            raise TransportError("timed out after %.1fs talking to %s" % (self.timeout, self.url))
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, socket.timeout):
                raise TransportError("timed out after %.1fs talking to %s" % (self.timeout, self.url))
            raise TransportError("cannot reach %s: %s" % (self.url, reason))
        except ssl.SSLError as exc:
            raise TransportError("TLS failure: %s (try --insecure)" % exc)
        except OSError as exc:
            raise TransportError("connection error: %s" % exc)

        elapsed = time.time() - started
        with self._lock:
            self.request_count += 1

        if headers.get("content-encoding", "").lower() == "gzip":
            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception:
                pass

        text = raw_bytes.decode("utf-8", errors="replace")

        if self.verbose:
            note("%s -> HTTP %d, %d bytes, %.3fs" % (label, status, len(raw_bytes), elapsed))

        if not raw_bytes.strip():
            raise ProtocolError(
                "empty response body (HTTP %d) from %s" % (status, self.url),
                raw_body=raw_bytes, status=status,
            )

        try:
            values, _ = xmlrpc.client.loads(raw_bytes)
        except xmlrpc.client.Fault as fault:
            raise RPCFault(fault.faultCode, fault.faultString, raw=text)
        except Exception as exc:
            snippet = re.sub(r"\s+", " ", text)[:200]
            raise ProtocolError(
                "response is not XML-RPC (HTTP %d): %s | body starts: %s"
                % (status, exc, snippet),
                raw_body=raw_bytes, status=status,
            )

        value = values[0] if values else None
        return RPCResult(
            value=value,
            raw=text,
            status=status,
            elapsed=elapsed,
            bytes_in=len(raw_bytes),
            headers=headers,
        )

    # -- high level --------------------------------------------------------

    def call(self, method: str, *params: Any) -> RPCResult:
        """Invoke one XML-RPC method."""
        try:
            body = xmlrpc.client.dumps(
                tuple(params), methodname=method, allow_none=True, encoding="utf-8"
            ).encode("utf-8")
        except Exception as exc:
            raise RPCError("cannot serialise arguments for %s: %s" % (method, exc))
        return self.post_raw(body, label=method)

    def call_value(self, method: str, *params: Any) -> Any:
        return self.call(method, *params).value

    def multicall(self, calls: Sequence[Dict[str, Any]]) -> RPCResult:
        """system.multicall: many method calls inside a single HTTP request."""
        return self.call("system.multicall", list(calls))

    def post_raw_http(self, body: bytes, label: str = "raw POST") -> Tuple[int, Dict[str, str], str]:
        """
        POST a raw body and return (status, headers, text) WITHOUT trying to
        parse it as XML-RPC. Needed for parser-fuzzing payloads, whose whole
        purpose is to make the XML parser behave unusually.
        """
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "Accept": "text/xml",
                "User-Agent": self.user_agent,
                "Connection": "close",
            },
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = getattr(resp, "status", resp.getcode())
                headers = {k.lower(): v for k, v in resp.headers.items()}
                raw = resp.read(200000)
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
            try:
                raw = exc.read(200000)
            except Exception:
                raw = b""
        except Exception as exc:
            raise TransportError("raw POST failed: %s" % exc)
        with self._lock:
            self.request_count += 1
        return status, headers, raw.decode("utf-8", errors="replace")

    # -- probing -----------------------------------------------------------

    def http_probe(self, method: str = "GET") -> Tuple[int, Dict[str, str], str]:
        """Plain HTTP probe of the endpoint, for status/header fingerprinting."""
        req = urllib.request.Request(
            self.url,
            method=method,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                return getattr(resp, "status", resp.getcode()), {
                    k.lower(): v for k, v in resp.headers.items()
                }, body
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read(4096).decode("utf-8", errors="replace")
            except Exception:
                pass
            return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, body
        except Exception as exc:
            raise TransportError("HTTP probe failed: %s" % exc)


class WPSession:
    """
    A minimal cookie-jar HTTP client for the WordPress admin endpoints.

    The XML-RPC client cannot do this: exploits like CVE-2019-8942 need a
    logged-in cookie, multipart uploads, hidden form nonces and redirects.
    This class is deliberately small and stdlib-only, mirroring RPCClient's
    transport settings (proxy, TLS, UA, timeout, delay).
    """

    def __init__(self, base_url: str, client: RPCClient) -> None:
        self.base = base_url.rstrip("/") + "/"
        self.client = client
        self.cookies: Dict[str, str] = {}
        self._opener = client._opener  # reuse proxy / TLS configuration

    def _jar(self) -> str:
        return "; ".join("%s=%s" % kv for kv in self.cookies.items())

    def _absorb_cookies(self, headers: Any) -> None:
        for raw in (headers.get_all("Set-Cookie") or []) if hasattr(headers, "get_all") else []:
            pair = raw.split(";", 1)[0]
            if "=" in pair:
                k, v = pair.split("=", 1)
                self.cookies[k.strip()] = v.strip()

    def request(
        self,
        path: str,
        method: str = "GET",
        data: Optional[bytes] = None,
        form: Optional[Dict[str, str]] = None,
        content_type: Optional[str] = None,
        follow: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, Any]:
        """Issue a request. Returns (status, body, headers)."""
        if self.client.delay:
            time.sleep(self.client.delay)
        url = urllib.parse.urljoin(self.base, path.lstrip("/"))
        headers: Dict[str, str] = {
            "User-Agent": self.client.user_agent,
            "Accept": "*/*",
            "Connection": "close",
        }
        if self.cookies:
            headers["Cookie"] = self._jar()
        if form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"
        if content_type:
            headers["Content-Type"] = content_type
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=data, method=method, headers=headers)

        # No automatic redirect following: we need to observe 302s and keep
        # the cookie jar consistent across the login flow.
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None

        opener = urllib.request.build_opener(self.client._opener.handlers[0])
        # Rebuild with the same proxy/TLS handlers but no redirects.
        handlers = [h for h in self.client._opener.handlers
                    if not isinstance(h, urllib.request.HTTPRedirectHandler)]
        opener = urllib.request.build_opener(*handlers, _NoRedirect())

        try:
            with opener.open(req, timeout=self.client.timeout) as resp:
                status = getattr(resp, "status", resp.getcode())
                body = resp.read(2000000).decode("utf-8", errors="replace")
                hdrs = resp.headers
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body = exc.read(2000000).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            hdrs = exc.headers or {}
        except Exception as exc:
            raise TransportError("WPSession request to %s failed: %s" % (url, exc))

        self._absorb_cookies(hdrs)

        if follow and status in (301, 302, 303, 307, 308):
            loc = hdrs.get("Location")
            if loc:
                return self.request(loc, method="GET", follow=follow)
        return status, body, hdrs

    def login(self, username: str, password: str) -> bool:
        """Authenticate through wp-login.php. Returns True on success."""
        status, body, _ = self.request("wp-login.php")
        if status != 200:
            return False
        form = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": urllib.parse.urljoin(self.base, "wp-admin/"),
            "testcookie": "1",
        }
        # WordPress sets a test cookie on the initial GET.
        self.cookies.setdefault("wordpress_test_cookie", "WP+Cookie+check")
        status, body, hdrs = self.request("wp-login.php", method="POST", form=form)
        return "wordpress_logged_in" in self._jar() or status in (301, 302)

    @staticmethod
    def hidden_inputs(body: str) -> Dict[str, str]:
        """Parse <input type=hidden name=... value=...> pairs from HTML."""
        out: Dict[str, str] = {}
        for m in re.finditer(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            body, re.I,
        ):
            out[m.group(1)] = html.unescape(m.group(2))
        for m in re.finditer(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*type=["\']hidden["\']',
            body, re.I,
        ):
            out.setdefault(m.group(1), html.unescape(m.group(2)))
        return out

    def multipart(self, path: str, fields: Dict[str, str],
                  file_field: str, file_name: str,
                  file_data: bytes, file_type: str = "image/jpeg") -> Tuple[int, str, Any]:
        """Send a multipart/form-data POST (used for the image upload)."""
        boundary = "----xploitrpc" + "".join(random.choice(string.ascii_letters) for _ in range(20))
        parts: List[bytes] = []
        for k, v in fields.items():
            parts.append(
                ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                 % (boundary, k, v)).encode("utf-8", errors="replace")
            )
        parts.append(
            ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
             "Content-Type: %s\r\n\r\n" % (boundary, file_field, file_name, file_type)).encode("utf-8")
            + file_data + b"\r\n"
        )
        parts.append(("--%s--\r\n" % boundary).encode("utf-8"))
        body = b"".join(parts)
        return self.request(
            path, method="POST", data=body,
            content_type="multipart/form-data; boundary=%s" % boundary,
        )


def version_tuple(v: str) -> Tuple[int, ...]:
    """Parse a dotted version into an int tuple for range comparisons."""
    try:
        return tuple(int(p) for p in re.findall(r"\d+", v)[:3])
    except Exception:
        return (0,)


@dataclass
class State:
    url: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    blog_id: Optional[str] = None
    methods: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    probe: Dict[str, Any] = field(default_factory=dict)
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    report: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def has_creds(self) -> bool:
        return bool(self.username and self.password)

    def add_finding(self, severity: str, title: str, detail: str,
                    evidence: str = "") -> None:
        self.findings.append({
            "severity": severity, "title": title,
            "detail": detail, "evidence": evidence,
        })


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


SEVERITY_COLOR = {"critical": "red", "high": "red", "medium": "yellow",
                  "low": "cyan", "info": "grey"}


def print_findings(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        ok("No findings recorded.")
        return
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    print()
    head("Findings (%d)" % len(ordered))
    for i, f in enumerate(ordered, 1):
        color = SEVERITY_COLOR.get(f["severity"], "white")
        print()
        print("  %s [%s] %s" % (
            Term.paint("%2d." % i, "grey"),
            Term.paint(f["severity"].upper(), color, "bold"),
            Term.paint(f["title"], "bold")))
        print("      %s" % f["detail"])
        if f.get("evidence"):
            print("      %s %s" % (Term.paint("evidence:", "grey"), f["evidence"]))


def write_report(state: State, path: str, fmt: str = "json") -> None:
    payload = {
        "tool": "xploitrpc",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "target": state.url,
        "credentials_found": [
            {"username": c.username, "password": c.password, "blog_id": c.blog_id}
            for c in state.credentials
        ],
        "usernames": state.usernames,
        "methods": state.methods,
        "probe": state.probe,
        "fingerprint": state.fingerprint,
        "report": state.report,
    }
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    else:
        lines = [
            "# xploitrpc report",
            "",
            "- Target: %s" % state.url,
            "- Generated: %s" % payload["generated"],
            "- Methods advertised: %d" % len(state.methods),
            "- Usernames recovered: %s" % (", ".join(state.usernames) or "none"),
            "- Credentials found: %d" % len(state.credentials),
            "",
        ]
        if state.credentials:
            lines.append("## Credentials")
            for c in state.credentials:
                lines.append("- `%s:%s` (blog_id=%s)" % (c.username, c.password, c.blog_id))
            lines.append("")
        if state.fingerprint:
            lines.append("## Fingerprint")
            for k, v in state.fingerprint.items():
                if k in ("options", "plugins", "themes"):
                    continue
                lines.append("- %s: %s" % (k, v))
            lines.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    ok("Report written to %s" % path)


def print_banner() -> None:
    art = r"""
  __  ______  _       _ _   ____  ____   ____
  \ \/ /  _ \| | ___ (_) |_|  _ \|  _ \ / ___|
   \  /| |_) | |/ _ \| | __| |_) | |_) | |
   /  \|  __/| | (_) | | |_|  _ <|  __/| |___
  /_/\_\_|   |_|\___/|_|\__|_| \_\_|    \____|
"""
    print(Term.paint(art, "cyan"))
    print(Term.paint("  WordPress XML-RPC toolkit  v%s" % __version__, "bold", "white"))
    print(Term.paint("  Krishanu Bepari  -  github.com/kbepari52", "grey"))
    print(Term.paint("  Authorized testing only.", "yellow"))
    print()




# --- fault classification (shared by recon, auth, offense, data) ---
def is_disabled_fault(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(m in text for m in DISABLED_MARKERS)

def describe_fault(exc: RPCFault) -> str:
    name, meaning = WP_FAULTS.get(exc.code, ("unknown", "No known meaning for this code."))
    return "%s (%s): %s" % (name, exc.code, exc.message or meaning)

