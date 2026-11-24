#!/usr/bin/env python3
"""Look up published vulnerabilities for a firmware's third-party dependencies in OSV.dev.

  python3 osv_check.py <repo-root> [--components confirmed_components.json] [--dep URL@TAG ...] --out-dir DIR
  python3 osv_check.py ... --send

THIS SENDS DATA OFF THE MACHINE WHEN --send IS GIVEN. Without --send the script only prints the plan:
the exact host and request bodies it would send, and writes nothing else. The skill must show that plan
to the user and get a yes before running with --send.

What is sent: for each dependency, the public upstream repository URL and the git tag (for ModusToolbox
.mtb and west.yml entries) or the package URL (for components with a purl). Nothing else: no repo path,
project name, source code or findings. What it reveals: the list of third-party components and versions
this product uses. Queries go to https://api.osv.dev (Google-run; see https://osv.dev for its policies).

What comes back: OSV records (CVE / GHSA IDs, summary, severity) that list the queried version as
affected. These are PUBLISHED VULNERABILITIES IN THIRD-PARTY COMPONENTS, not defects in the code under
review, and OSV cannot say whether the affected feature is compiled in or reachable in this firmware.
Every hit is a lead to verify, never a finding on its own.

Coverage is partial. Libraries OSV tracks by git tag (zlib, lwIP, MCUboot, curl, OpenSSL, expat ...)
work. Some do not: mbedTLS records carry no version ranges and FreeRTOS kernel has no records, so a
zero for those means "not checkable here", not "clean". The script says which is which.

Outputs: osv_leads.md and osv_leads.json in --out-dir.
"""
import argparse
import datetime
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

OSV_HOST = "https://api.osv.dev"
USER_AGENT = "phazeone-amygdala/0.3 (OSV dependency lookup)"
TIMEOUT = 30

# Upstream aliases for vendor mirrors: query the mirror as given AND the upstream, because advisories are
# recorded against the upstream repository.
UPSTREAM = {
    "github.com/armmbed/mbedtls": "https://github.com/Mbed-TLS/mbedtls.git",
    "github.com/infineon/freertos": "https://github.com/FreeRTOS/FreeRTOS-Kernel.git",
    "github.com/infineon/lwip": "https://github.com/lwip-tcpip/lwip.git",
    "github.com/infineon/mcuboot": "https://github.com/mcu-tools/mcuboot.git",
    "github.com/infineon/mbedtls": "https://github.com/Mbed-TLS/mbedtls.git",
    "github.com/zephyrproject-rtos/mbedtls": "https://github.com/Mbed-TLS/mbedtls.git",
    "github.com/zephyrproject-rtos/mcuboot": "https://github.com/mcu-tools/mcuboot.git",
    "github.com/zephyrproject-rtos/zlib": "https://github.com/madler/zlib.git",
}

# Known OSV coverage limits (checked Nov 2026). A zero result for these is NOT evidence of a clean version.
NOT_VERSION_MATCHABLE = {
    "github.com/mbed-tls/mbedtls": "OSV holds mbedTLS CVEs but without version ranges, so no version matches. "
                                   "Check https://mbed-tls.readthedocs.io/en/latest/security-advisories/ manually.",
    "github.com/freertos/freertos-kernel": "OSV has no FreeRTOS kernel records. Check https://www.freertos.org/security/ manually.",
}
# Repositories where a git-tag query is known to return records when applicable, so a zero is meaningful.
KNOWN_TRACKED = {"github.com/madler/zlib", "github.com/lwip-tcpip/lwip", "github.com/mcu-tools/mcuboot",
                 "github.com/curl/curl", "github.com/openssl/openssl", "github.com/libexpat/libexpat"}


def norm_repo(url):
    u = url.strip()
    u = re.sub(r"^git@github\.com:", "https://github.com/", u)
    u = re.sub(r"^(https?://)?(www\.)?", "https://", u)
    if not u.endswith(".git"):
        u += ".git"
    return u


def repo_key(url):
    return re.sub(r"\.git$", "", re.sub(r"^https?://", "", norm_repo(url))).lower()


def collect_mtb(root):
    deps = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in {".git", "mtb_shared", "build", "node_modules"}]
        for f in fn:
            if f.endswith(".mtb"):
                try:
                    line = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read().strip().splitlines()[0]
                except (OSError, IndexError):
                    continue
                parts = line.split("#")
                if len(parts) >= 2 and parts[0].startswith("http"):
                    deps.append({"name": os.path.splitext(f)[0], "repo": norm_repo(parts[0]), "tag": parts[1],
                                 "source": os.path.relpath(os.path.join(dp, f), root)})
    return deps


def collect_west(root):
    """Minimal west.yml reader (no YAML dependency): remotes url-base + projects name/remote/url/revision."""
    deps = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in {".git", "build", "node_modules"}]
        if "west.yml" not in fn:
            continue
        text = open(os.path.join(dp, "west.yml"), encoding="utf-8", errors="replace").read()
        remotes = {}
        for m in re.finditer(r"-\s*name:\s*([\w.-]+)\s*\n\s*url-base:\s*(\S+)", text):
            remotes[m.group(1)] = m.group(2)
        default_remote = next(iter(remotes), None)
        # horizontal whitespace only inside the block: \s could also eat newlines, which makes the
        # repetition ambiguous and the match time explode on a long run of blank-ish lines
        m = re.search(r"defaults:[ \t]*\n(?:[ \t]+.*\n)*?[ \t]+remote:[ \t]*([\w.-]+)", text)
        if m:
            default_remote = m.group(1)
        proj_block = text.split("projects:", 1)[1] if "projects:" in text else ""
        for pm in re.finditer(r"-\s*name:\s*([\w.-]+)((?:\n\s{4,}.*)*)", proj_block):
            name, body = pm.group(1), pm.group(2)
            url = re.search(r"\n\s+url:\s*(\S+)", body)
            remote = re.search(r"\n\s+remote:\s*([\w.-]+)", body)
            rev = re.search(r"\n\s+revision:\s*(\S+)", body)
            repo_path = re.search(r"\n\s+repo-path:\s*(\S+)", body)
            base = remotes.get(remote.group(1) if remote else default_remote, "")
            repo = url.group(1) if url else (f"{base}/{repo_path.group(1) if repo_path else name}" if base else None)
            if not repo:
                continue
            revision = rev.group(1) if rev else None
            deps.append({"name": name, "repo": norm_repo(repo), "tag": revision,
                         "source": os.path.relpath(os.path.join(dp, "west.yml"), root),
                         "note": None if revision and not re.fullmatch(r"[0-9a-f]{40}|main|master|develop", revision)
                         else "revision is a branch or commit, not a release tag; OSV tag lookup needs a tag"})
    return deps


def collect_components(path):
    """Components from the amygdala:oss skill (confirmed_components.json) that carry a purl."""
    deps = []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as ex:
        sys.exit(f"could not read {path}: {ex}")
    comps = data if isinstance(data, list) else data.get("components", [])
    for c in comps:
        purl = c.get("purl")
        if not purl:
            continue
        m = re.match(r"pkg:github/([^/@]+)/([^/@]+)@(.+)$", purl)
        if m:
            deps.append({"name": c.get("name", m.group(2)), "repo": norm_repo(f"https://github.com/{m.group(1)}/{m.group(2)}"),
                         "tag": m.group(3), "source": os.path.basename(path)})
        else:
            deps.append({"name": c.get("name", purl), "purl": purl, "source": os.path.basename(path)})
    return deps


def build_queries(deps):
    """One or more OSV query bodies per dependency (mirror + upstream)."""
    plan = []
    for d in deps:
        if d.get("purl"):
            plan.append({"dep": d, "label": d["purl"], "body": {"package": {"purl": d["purl"]}}, "key": d["purl"]})
            continue
        if not d.get("tag"):
            plan.append({"dep": d, "label": f"{d['repo']} (no tag)", "body": None, "key": repo_key(d["repo"]),
                         "skip": d.get("note") or "no release tag"})
            continue
        targets = [d["repo"]]
        up = UPSTREAM.get(repo_key(d["repo"]))
        if up and up not in targets:
            targets.append(up)
        for t in targets:
            plan.append({"dep": d, "label": f"{t} @ {d['tag']}", "key": repo_key(t),
                         "body": {"package": {"name": t, "ecosystem": "GIT"}, "version": d["tag"]}})
    return plan


_SSL_CTX = None


def ssl_context():
    """A verifying TLS context. Some tool-bundled Pythons (PlatformIO, ModusToolbox) ship without a CA
    bundle, so fall back to certifi or the OS bundle. Verification is never disabled."""
    global _SSL_CTX
    if _SSL_CTX is not None:
        return _SSL_CTX
    ctx = ssl.create_default_context()
    if not ctx.get_ca_certs():
        cafile = None
        try:
            import certifi  # noqa: F401
            cafile = certifi.where()
        except ImportError:
            for c in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                      "/usr/local/etc/openssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem"):
                if os.path.isfile(c):
                    cafile = c
                    break
        if cafile:
            ctx = ssl.create_default_context(cafile=cafile)
    _SSL_CTX = ctx
    return ctx


def osv_query(body):
    req = urllib.request.Request(f"{OSV_HOST}/v1/query", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl_context()) as r:
            return json.load(r)
    except urllib.error.URLError as ex:
        if "CERTIFICATE_VERIFY_FAILED" in str(ex):
            raise RuntimeError("TLS certificate verification failed: this Python has no CA bundle. Run the script with the "
                               "system Python (e.g. /usr/bin/python3) or `python3 -m pip install --user certifi`. "
                               "Verification is never disabled.") from ex
        raise


def severity_of(v):
    for s in v.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS"):
            return s.get("score", "")
    ds = v.get("database_specific") or {}
    return ds.get("severity", "") or ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="repository root (scanned for *.mtb and west.yml)")
    ap.add_argument("--components", help="confirmed_components.json from the amygdala:oss skill")
    ap.add_argument("--dep", action="append", default=[], metavar="URL@TAG", help="extra dependency, e.g. https://github.com/madler/zlib@v1.2.11")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--send", action="store_true", help="actually send the queries to api.osv.dev (only after the user agreed)")
    args = ap.parse_args()

    deps = collect_mtb(args.root) + collect_west(args.root)
    if args.components:
        deps += collect_components(args.components)
    for x in args.dep:
        if "@" not in x:
            sys.exit(f"--dep needs URL@TAG, got {x}")
        repo, tag = x.rsplit("@", 1)
        deps.append({"name": repo.rstrip("/").split("/")[-1], "repo": norm_repo(repo), "tag": tag, "source": "--dep"})
    # de-duplicate
    seen, uniq = set(), []
    for d in deps:
        k = (d.get("repo"), d.get("tag"), d.get("purl"))
        if k not in seen:
            seen.add(k); uniq.append(d)
    deps = uniq
    plan = build_queries(deps)
    sendable = [p for p in plan if p.get("body")]

    print(f"dependencies found: {len(deps)}  queries: {len(sendable)}  host: {OSV_HOST}")
    print("DATA THAT WOULD LEAVE THIS MACHINE (public upstream repo URL + tag, or purl; nothing else):")
    for p in plan:
        print(f"  {'SKIP ' if not p.get('body') else 'SEND '}{p['label']}" + (f"   [{p['skip']}]" if p.get("skip") else ""))
    if not args.send:
        print("\nPlan only; nothing was sent. Re-run with --send after the user has agreed.")
        os.makedirs(args.out_dir, exist_ok=True)
        json.dump({"mode": "plan", "host": OSV_HOST, "queries": [p["body"] for p in sendable], "dependencies": deps},
                  open(os.path.join(args.out_dir, "osv_plan.json"), "w", encoding="utf-8"), indent=1)
        print(f"wrote {os.path.join(args.out_dir, 'osv_plan.json')}")
        return

    results, errors = [], []
    for p in sendable:
        try:
            r = osv_query(p["body"])
            vulns = r.get("vulns", []) or []
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError, RuntimeError) as ex:
            errors.append(f"{p['label']}: {ex}")
            if isinstance(ex, RuntimeError):   # CA bundle problem: every query will fail the same way
                break
            continue
        key = p["key"]
        if vulns:
            coverage = "records returned"
        elif key in NOT_VERSION_MATCHABLE:
            coverage = "NOT CHECKABLE: " + NOT_VERSION_MATCHABLE[key]
        elif key in KNOWN_TRACKED:
            coverage = "tracked by OSV; no records list this version as affected"
        else:
            coverage = "no records; OSV coverage of this repository is unknown, so this is not evidence of a clean version"
        results.append({"dependency": p["dep"]["name"], "queried": p["label"], "source": p["dep"].get("source"),
                        "coverage": coverage, "count": len(vulns),
                        "vulns": [{"id": v.get("id"), "aliases": v.get("aliases", []), "summary": (v.get("summary") or v.get("details", ""))[:300],
                                   "severity": severity_of(v), "published": v.get("published", "")[:10],
                                   "url": f"https://osv.dev/vulnerability/{v.get('id')}"} for v in vulns[:50]],
                        "truncated": len(vulns) > 50})

    os.makedirs(args.out_dir, exist_ok=True)
    stamp = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    total = sum(r["count"] for r in results)
    out = {"mode": "sent", "host": OSV_HOST, "queried_at": stamp, "results": results, "errors": errors,
           "skipped": [{"dependency": p["dep"]["name"], "reason": p.get("skip")} for p in plan if not p.get("body")],
           "tools_entry": {"name": "OSV.dev dependency lookup", "status": "ran" if results else "failed",
                           "notes": (f"{len(results)} of {len(sendable)} queries answered by api.osv.dev with the user's consent on {stamp}; "
                                     f"{total} published advisories matched across {sum(1 for r in results if r['count'])} components. "
                                     "Third-party records; applicability to this firmware assessed per finding."
                                     + (f" {len(errors)} queries failed: {errors[0][:160]}" if errors else ""))
                           if results else
                           (f"Lookup attempted on {stamp} with consent but no query succeeded: {errors[0][:200] if errors else 'no queries'}. "
                            "Dependency vulnerability status not checked.")}}
    json.dump(out, open(os.path.join(args.out_dir, "osv_leads.json"), "w", encoding="utf-8"), indent=1)

    L = [f"# Known vulnerabilities in third-party dependencies (OSV.dev)", "",
         f"Queried {len(sendable)} identifiers at {OSV_HOST} on {stamp} with the user's consent. "
         "Only public upstream repository URLs with tags (or package URLs) were sent.", "",
         "**Read this before using the results.** These are vulnerabilities *published for the third-party components* "
         "listed below, not defects in the first-party code under review. OSV matches on version only; it cannot tell "
         "whether the affected feature is compiled in, configured on, or reachable from any input in this firmware. "
         "Treat each entry as a lead: confirm applicability in the code and build configuration before it becomes a "
         "finding, and say in the finding that it is a third-party component issue (`origin: third-party`).", ""]
    for r in results:
        L.append(f"## {r['dependency']} — {r['queried']}")
        L.append(f"Source: `{r['source']}` · Coverage: {r['coverage']} · Matched: {r['count']}" + (" (showing 50)" if r["truncated"] else ""))
        L.append("")
        for v in r["vulns"]:
            al = (" (" + ", ".join(v["aliases"][:3]) + ")") if v["aliases"] else ""
            sev = f" · {v['severity']}" if v["severity"] else ""
            L.append(f"- [{v['id']}]({v['url']}){al}{sev} · {v['published']} — {v['summary']}")
        L.append("")
    if out["skipped"]:
        L += ["## Not queried", ""] + [f"- {s['dependency']}: {s['reason']}" for s in out["skipped"]] + [""]
    if errors:
        L += ["## Errors", ""] + [f"- {x}" for x in errors] + [""]
    open(os.path.join(args.out_dir, "osv_leads.md"), "w", encoding="utf-8").write("\n".join(L))
    print(f"\n{total} published advisories matched across {sum(1 for r in results if r['count'])} of {len(results)} queries"
          + (f"; {len(errors)} errors" if errors else ""))
    for n in ("osv_leads.md", "osv_leads.json"):
        print("wrote", os.path.join(args.out_dir, n))


if __name__ == "__main__":
    main()
