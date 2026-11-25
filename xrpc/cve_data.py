"""xrpc.cve_data - WordPress version -> RCE / XML-RPC CVE knowledge base.

Every range is grounded in a public advisory (source URL on each record).

IMPORTANT: WordPress BACKPORTS security fixes to older supported branches.
A naive "version < mainline_fix" comparison is WRONG: e.g. 4.9.26 is a 2022
backport release and is NOT vulnerable to a 2019 bug fixed in 4.9.9. Each
record therefore stores per-branch fix floors in `branch_fixes`. A version is
vulnerable only if its own branch's patch level is below that branch's floor.
Branches with no known floor are reported as ambiguous, never as a confirmed hit.

`tool_module` is honest: only exploits the toolkit actually implements are named;
everything else is assessment-only.
"""

from typing import Any, Dict, List

WPCVE_DB: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2019-8942",
        "title": "crop-image RCE via _wp_attached_file meta poisoning",
        "branch_fixes": {(4, 9): (4, 9, 9), (5, 0): (5, 0, 1)},
        "mainline_fix": (5, 0, 1),
        "auth": "author", "xmlrpc": True, "impact": "RCE",
        "tool_module": "exploit crop",
        "source": "https://github.com/advisories/GHSA-rwhm-6hw4-9fgg",
    },
    {
        "cve": "CVE-2019-8943",
        "title": "path traversal in wp_crop_image() (crop-chain file write)",
        "branch_fixes": {(4, 9): (4, 9, 9), (5, 0): (5, 0, 4)},
        "mainline_fix": (5, 0, 4),
        "auth": "author", "xmlrpc": True, "impact": "file write / RCE chain",
        "tool_module": "exploit crop (combined with 8942)",
        "source": "https://github.com/advisories/ghsa-558v-vpgj-m324",
    },
    {
        "cve": "CVE-2020-28035",
        "title": "privilege escalation via XML-RPC",
        "branch_fixes": {(5, 5): (5, 5, 2), (5, 4): (5, 4, 4), (5, 3): (5, 3, 6),
                         (4, 9): (4, 9, 16)},
        "mainline_fix": (5, 5, 2),
        "auth": "none (escalation)", "xmlrpc": True, "impact": "privilege escalation",
        "tool_module": None,
        "source": "https://www.cisa.gov/news-events/bulletins/sb20-314",
    },
    {
        "cve": "CVE-2020-28036",
        "title": "privilege escalation via XML-RPC comment on a post",
        "branch_fixes": {(5, 5): (5, 5, 2), (5, 4): (5, 4, 4), (5, 3): (5, 3, 6),
                         (4, 9): (4, 9, 16)},
        "mainline_fix": (5, 5, 2),
        "auth": "none (escalation)", "xmlrpc": True, "impact": "privilege escalation",
        "tool_module": None,
        "source": "https://www.cisa.gov/news-events/bulletins/sb20-314",
    },
    {
        "cve": "CVE-2026-65640",
        "title": "Imagick/Ghostscript RCE via malicious file upload (wp.uploadFile is an affected path)",
        "branch_fixes": {},
        "mainline_fix": (7, 0, 4), "introduced": (4, 7, 0),
        "auth": "author (upload_files)", "xmlrpc": True,
        "impact": "RCE (requires Imagick + Ghostscript)",
        "tool_module": None,
        "note": "Backported to all branches down to 4.7; verify exact patch level.",
        "source": "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8vr3-7mxf-gx8w",
    },
    {
        "cve": "CVE-2025-54352",
        "title": "private/draft post title disclosure via pingback.ping",
        "branch_fixes": {},
        "mainline_fix": (6, 8, 3), "introduced": (3, 5, 0),
        "auth": "none", "xmlrpc": True, "impact": "information disclosure",
        "tool_module": "pingback (probe only)",
        "note": "Supplier is not changing this behaviour; treat as informational.",
        "source": "https://github.com/advisories/GHSA-585c-5qcq-7fgc",
    },
    {
        "cve": "CVE-2007-1897",
        "title": "SQL injection in XML-RPC mt.setPostCategories",
        "branch_fixes": {(2, 1): (2, 1, 3)},
        "mainline_fix": (2, 1, 3),
        "auth": "authenticated", "xmlrpc": True, "impact": "SQL injection",
        "tool_module": None,
        "source": "https://github.com/advisories/GHSA-pp8c-8h35-cghc",
    },
    {
        "cve": "CVE-2026-87902",
        "title": "page-template path traversal -> conditional unauthenticated RCE",
        "branch_fixes": {(7, 1): (7, 1, 2), (7, 0): (7, 0, 6),
                         (6, 8): (6, 8, 10), (4, 7): (4, 7, 37)},
        "mainline_fix": (7, 1, 2), "introduced": (4, 7, 0),
        "auth": "none", "xmlrpc": False, "impact": "LFI -> conditional RCE",
        "tool_module": None,
        "note": "Not an XML-RPC vector. Requires a page-* theme directory and a readable local PHP file.",
        "source": "https://www.crowdsec.net/vulntracking-report/cve-2026-87902-wordpress-vulnerability",
    },
]
