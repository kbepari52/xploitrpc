# xploitrpc

A modular WordPress XML-RPC attack-surface toolkit for **authorized** penetration
testing and security research. Standard library only, no third-party
dependencies. Runs on Windows, macOS and Linux.

It maps what an XML-RPC endpoint exposes, fingerprints the underlying WordPress
stack, enumerates users, checks REST hardening, mines public content for
credential clues, and rates findings into a report. It also contains gated
offensive modules (credential testing, multicall amplification, pingback SSRF,
XML parser attacks, authenticated state changes and a crop-image RCE chain).

> **Authorized use only.** See [Ethical disclaimer](#ethical-disclaimer).

---

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Local vulnerable lab](#local-vulnerable-lab)
- [Real-target validation](#real-target-validation)
- [Architecture](#architecture)
- [Commands](#commands)
- [Global options](#global-options)
- [Modules and what they do](#modules-and-what-they-do)
- [Authorization gates](#authorization-gates)
- [CVE knowledge base](#cve-knowledge-base)
- [Reports](#reports)
- [Known limitations](#known-limitations)
- [Ethical disclaimer](#ethical-disclaimer)

---

## Installation

Python 3.8 or newer. No packages to install.

```bash
git clone https://github.com/kbepari52/xploitrpc.git
cd xploitrpc
python xploitrpc.py --help
```

Optional, to install as a console command:

```bash
python -m pip install -e .
xploitrpc --help
```

Verify the install:

```bash
python xploitrpc.py --version
python -m compileall -q xrpc xploitrpc.py
```

---

## Quick start

```bash
# Is XML-RPC live, and what does it advertise?
python xploitrpc.py -u https://target.example/xmlrpc.php probe

# Full read-only assessment with a findings report
python xploitrpc.py -u https://target.example/ audit -o audit.md

# Which known RCEs match the detected WordPress version?
python xploitrpc.py -u https://target.example/ cves --xmlrpc-only

# Interactive menu
python xploitrpc.py -u https://target.example/ menu
```

A bare host is fine: `xploitrpc.py` appends `/xmlrpc.php` automatically.

---

## Local vulnerable lab

A reproducible WordPress target is included. It runs a genuine WordPress 5.0
install in Docker with a MySQL database and a real filesystem. The Dockerfile
replaces the image's patched core with the WordPress 5.0 release from
wordpress.org and installs a must-use plugin that blocks auto-updates, so the
lab stays vulnerable across restarts. Every byte the toolkit parses comes from
this live stack.

Verified end-to-end on this lab: `exploit crop` produced real command output
`uid=33(www-data) gid=33(www-data)`, and a token round-trip
(`echo X7kP2mQ9vL4nR8zZ`) matched exactly.

```bash
docker compose up -d --build     # WordPress on http://127.0.0.1:8080/
python lab_setup.py              # installs WP and creates the Author account
```

Wait for the container to become healthy before running `lab_setup.py`.
Confirm the lab is still vulnerable with
`docker exec xrpc-wordpress grep 'wp_version =' /var/www/html/wp-includes/version.php`
(it must report `5.0`, not `5.0.32`). Credentials created by the bootstrap (lab only):

| Role | Username | Password |
| --- | --- | --- |
| Administrator | `labadmin` | `Lab_Pass_2026!` |
| Author | `labauthor` | `Author_Pass_2026` |

The Apache image is built with a `Dockerfile` that also listens on port 8080
*inside* the container. This matters: the CVE-2019-8942 chain poisons
`_wp_attached_file` with a `?` suffix, which forces WordPress to load the
source image through its own URL. If the internal URL is unreachable, the
crop fails with `Image could not be processed.` even on a vulnerable version.

Example authenticated exploit run against the lab:

```bash
echo I-OWN-THIS-TARGET | python xploitrpc.py \
  --no-banner -u http://127.0.0.1:8080/ \
  --user labauthor --password Author_Pass_2026 \
  exploit crop --cmd id --confirmed
```

---

## Real-target validation

The toolkit works exclusively through live network I/O. It uses `urllib` and
raw XML building against live targets and parses the server's actual
responses.

Success is reported only on evidence from the target:

- RCE requires a well-formed `uid=N(name) gid=N(name)` line from command
  output, or an exact token round-trip (`echo <token>`). The command string
  itself, an HTTP 200, or a generic word like `id` in HTML never counts.
- Uploads are confirmed from the server's own JSON/XML-RPC response.
- Version and CVE claims come from the target's real responses and the
  bundled advisory data, with branch-aware backport uncertainty labelled.

Failed exploitation is reported as failed. A failed crop is not treated as
proof that a target is patched.

---

## Architecture

The original single-file tool was split into a package. `xploitrpc.py` is now a
thin compatibility shim; the implementation lives in `xrpc/`.

```
xploitrpc/                  project root
├── xploitrpc.py            entry point (python xploitrpc.py ...)
├── pyproject.toml          optional pip/console-script metadata
├── .gitignore
├── README.md
└── xrpc/                   implementation package
    ├── __init__.py         package version
    ├── core.py             HTTP/XML-RPC client, session, state, output helpers
    ├── payloads.py         static payloads and wordlists
    ├── cve_data.py         version -> CVE knowledge base (branch-aware)
    ├── cve.py              version/CVE assessment and the `cves` command
    ├── recon.py            probe, fingerprint, enumeration, REST/OSINT checks
    ├── auth.py             credential derivation, lockout detection, brute force
    ├── offense.py          exploit, parser attacks, amplification, pingback, postauth
    ├── data.py             raw method calls and authenticated dumps
    ├── audit.py            read-only capstone audit
    ├── cli.py              argument parser, dispatch and interactive menu
    └── wpcompat.py         version/PHP/WAF compatibility data and classification
```

Concerns are separated: transport and state in `core`, data in `payloads` and
`cve_data`, observation in `recon`, active tests in `auth`/`offense`, reporting
in `audit`, and user interface in `cli`.

---

## Commands

| Command | Purpose | Auth | Gated |
| --- | --- | --- | --- |
| `menu` | Interactive menu | varies | varies |
| `probe` | Reachability, stack, TLS, WAF, method count | no | no |
| `list` | List advertised XML-RPC methods | no | no |
| `fingerprint` | WordPress version, PHP, themes, plugins, options | optional | no |
| `users` | Enumerate usernames via REST/author IDs | no | no |
| `brute` | Credential testing with lockout detection | no | no |
| `multicall` | `system.multicall` amplification measurement | no | no |
| `pingback` | Pingback SSRF reachability probe | no | no |
| `xmlattack` | XXE / entity expansion / malformed XML probes | no | **yes** |
| `cves` | Map a WordPress version to known RCEs | no | no |
| `call` | Invoke one XML-RPC method with parsed arguments | optional | no |
| `dump` | Authenticated profile, options, users, posts, comments | yes | no |
| `scan` | Full unauthenticated scan | no | no |
| `audit` | Full read-only audit with severity findings | no | no |
| `restcheck` | REST API hardening check | no | no |
| `osint` | Mine public posts/comments for password clues | no | no |
| `exploit` | CVE exploit modules (`crop`, `upload`) | yes | **yes** |
| `postauth` | Authenticated state-changing actions | yes | **yes** |
| `discover` | Find XML-RPC at common alternate paths | no | no |
| `matrix` | Test which advertised methods actually work | no | no |

---

## Global options

```
-u, --url URL          Target URL (bare host gets /xmlrpc.php appended)
--user USER            Username for authenticated modules
--password PASSWORD    Password for authenticated modules
--blog-id BLOG_ID      WordPress blog id (auto-resolved if omitted)
--timeout TIMEOUT      Per-request timeout in seconds (default 15)
--delay DELAY          Delay between requests in seconds (default 0)
--retries RETRIES      Transport retries on failure (default 1)
--insecure             Skip TLS certificate verification
--proxy PROXY          HTTP proxy, e.g. http://127.0.0.1:8080
--user-agent UA        Custom User-Agent
-v, --verbose          Per-request diagnostics
--no-color             Disable ANSI colour
--no-banner            Suppress the banner
-o, --output PATH      Write report to .json or .md
--version              Print version and exit
```

TLS certificates are verified by default. `--insecure` disables verification
and is recorded as a finding in audit reports.

---

## Modules and what they do

### Reconnaissance

- **`probe`** checks GET/POST behaviour, server and WAF headers, the WordPress
  method signature, response timing and payload size.
- **`list`** calls `system.listMethods` and prints the advertised surface.
- **`fingerprint`** reads the generator tag, `wp.getOptions` (when authenticated),
  theme and plugin clues, and PHP version from headers.
- **`users`** enumerates via REST `/wp/v2/users` and `?author=N`.
- **`discover`** tries nine common XML-RPC paths, including plain-permalink
  REST routes.
- **`matrix`** probes each advertised method and classifies it as working,
  bad-arguments or authentication-required.
- **`restcheck`** checks the REST index, namespaces, user disclosure,
  `context=edit` and application-password availability.
- **`osint`** mines public posts and comments for username/password clues.

### Credential testing

- **`brute`** supports wordlists, derived candidates (`--derive --osint`),
  single-request or `--multicall` modes, and lockout detection. Single-request
  mode is the default: WordPress core short-circuits later auth calls in a
  multicall after the first failure, which causes false negatives. Hits found
  in multicall mode are re-verified.

### Active tests (gated)

- **`multicall`** measures unauthenticated amplification by batching
  `system.listMethods` calls in one request.
- **`pingback`** tests `pingback.ping` reachability. Fault 0 is reported as
  inconclusive, not as "disabled": WordPress rejects private/loopback source
  addresses before the HTTP callback fires.
- **`xmlattack`** sends raw XML parser payloads (XXE, entity expansion,
  malformed XML). Classification inspects the response **body**, because
  XML-RPC faults arrive as HTTP 200.
- **`postauth`** performs authenticated state-changing actions such as file
  upload. Never run automatically by `audit` or `scan`.
- **`exploit crop`** implements the CVE-2019-8942/8943 chain: cookie login,
  theme detection, nonce harvesting, JPEG upload, poisoned crops, template
  inclusion and command execution. The payload is the exact 758-byte JPEG
  from the upstream Metasploit module; an earlier truncated copy was
  undecodable by GD. Crop requests use the `nonce` field required by
  WordPress 5.0's `wp_ajax_crop_image` handler, and POST redirects are not
  followed (following them turns the POST into a GET and drops the body).
- **`exploit upload`** uses the XML-RPC `wp.uploadFile` method to place a PHP
  payload in `wp-content/uploads`, then attempts a page-template include and
  command execution. It reports the real upload response and tries multiple
  traversal depths. It never claims RCE without matching command output.

### Reporting

- **`audit`** chains the read-only modules and emits severity-rated findings.
  It deliberately excludes brute force, amplification, pingback and parser
  attacks, which remain behind their own explicit commands.
- **`cves`** maps a version to known RCE/exploitation CVEs with advisory
  sources and honest labels: `EXPLOIT MODULE`, `probe only` or
  `assessment only`.

---

## Authorization gates

`xmlattack`, `postauth` and `exploit` refuse to run unless **all** of the
following hold:

1. Valid credentials where the module requires them.
2. An explicit `--confirmed` flag.
3. A typed `I-OWN-THIS-TARGET` confirmation at the keyboard.

There is no non-interactive bypass. These gates have regression tests in the
development history and are enforced before any state-changing request.

---

## CVE knowledge base

`cves` covers eight records:

| CVE | Impact | Auth | XML-RPC | Tool |
| --- | --- | --- | --- | --- |
| CVE-2019-8942 | `_wp_attached_file` RCE | Author | yes | `exploit crop` |
| CVE-2019-8943 | `wp_crop_image()` traversal | Author | yes | `exploit crop` |
| CVE-2020-28035 / 28036 | XML-RPC privilege escalation | none | yes | assessment |
| CVE-2026-65640 | Imagick/Ghostscript upload RCE | Author | yes | assessment |
| CVE-2025-54352 | draft/private title disclosure via pingback | none | yes | `pingback` probe |
| CVE-2007-1897 | SQLi in `mt.setPostCategories` | auth | yes | assessment |
| CVE-2026-87902 | page-template LFI → conditional RCE | none | no | assessment |

Ranges are **branch-aware**. WordPress backports security fixes to older
supported branches, so a naive `version < mainline_fix` comparison produces
false positives: **4.9.26** is a 2022 backport release and is *not* vulnerable
to the 2019 crop RCE fixed in 4.9.9. Each record stores per-branch fix floors;
a version is only a confirmed hit when its own branch's patch level is below
that branch's floor. Unknown branches are labelled `backport uncertain -
verify` and never trigger an exploit finding.

Plugin and theme CVEs are out of scope.

---

## Reports

```bash
python xploitrpc.py -u https://target/ audit -o report.md
python xploitrpc.py -u https://target/ scan -o report.json
```

Markdown reports contain the target, timestamp and severity-rated findings.
JSON reports contain structured module output suitable for scripting.

---

## Known limitations

- Version matching is advisory-based and cannot see a target's actual patch
  state. Verify before drawing conclusions.
- Pingback SSRF is inconclusive without an external callback listener.
- The crop-image RCE depends on theme structure, GD/Imagick behaviour,
  upload permissions and the target's internal URL being reachable (the
  poisoned `?` path forces WordPress to load the source image over HTTP).
  A failed crop is not proof of a patched target.
- `exploit upload` depends on the uploaded file being includable as a page
  template. Many hardened setups store uploads outside the theme path or
  disable PHP execution there; in those cases it reports the upload but not
  RCE.
- Plugin and theme vulnerabilities are not in the CVE knowledge base.
- Cloudflare or other WAFs may block XML-RPC entirely; `discover` distinguishes
  a blocked endpoint from a missing one where possible.

---

## Ethical disclaimer

This tool is provided for **authorized security testing and research only**.
Do not use it against any computer system, network or website without explicit
written permission from the owner. Unauthorized access, credential testing,
denial of service and exploitation may be illegal in your jurisdiction and can
result in criminal and civil liability.

By using this software you agree that:

- you have authorization to test every target you point it at;
- you will respect privacy and data protection obligations;
- you will use the gated offensive modules only on systems you own or are
  explicitly authorized to compromise;
- the authors are not liable for misuse or damage caused by this tool.

The authors are not responsible for any unauthorized or illegal use. Use
responsibly, and leave systems better than you found them.

---

**License:** MIT  
**Author:** Krishanu Bepari (github.com/kbepari52)  
**Version:** 2.0.0
