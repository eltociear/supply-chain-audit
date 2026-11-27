#!/usr/bin/env python3
"""Regenerate family_stats.json and the README's number sections from the scanners' own docs.

  python3 scripts/gen_stats.py                  # fetch docs at the vendored commits, write both
  python3 scripts/gen_stats.py --from DIR       # read DIR/<repo> clones (git show <commit>:<doc>)
  python3 scripts/gen_stats.py --check          # exit 1 if family_stats.json / README would change
  python3 scripts/gen_stats.py --render-only    # re-render README from family_stats.json (offline)
  python3 scripts/gen_stats.py --also-write P   # also write the JSON to P

Every number comes from a scanner repo's FINDINGS.md / RECALL.md *at the commit vendored in
scanners/VERSIONS.json*, through the literal quotes in scripts/family_sources.json: a quote is
text that must still be in the doc, with {#} marking the integer(s) to read. When a doc changes
so that a quote stops matching, this script fails with the repo, field and quote instead of
letting the README drift. Text fields (ecosystem, notes, notable findings) are curated in
family_sources.json and are not checked. Canary/benign-control counts come from
tests/canaries.py, i.e. from the vendored test tables themselves.

Zero dependencies. Network only without --from (raw.githubusercontent.com, IPv4, 4 attempts).
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import sca  # noqa: E402

SOURCES = os.path.join(ROOT, "scripts", "family_sources.json")
STATS = os.path.join(ROOT, "family_stats.json")
README = os.path.join(ROOT, "README.md")
OWNER = "eltociear"
NUM = r"(\d[\d,]*)"
FP_FIELDS = ("calibration_n", "heldout_n", "heldout_highplus_count", "heldout_highplus_fp_count")


class Drift(Exception):
    pass


# ---------------------------------------------------------------- fetching docs

def _ipv4_only():
    orig = socket.getaddrinfo

    def gai(host, *a, **k):
        res = orig(host, *a, **k)
        v4 = [r for r in res if r[0] == socket.AF_INET]
        return v4 or res
    socket.getaddrinfo = gai


class Docs:
    def __init__(self, from_dir=None):
        self.from_dir = from_dir
        self.cache = {}

    def get(self, repo, commit, name):
        key = (repo, commit, name)
        if key not in self.cache:
            self.cache[key] = self._read(repo, commit, name)
        return self.cache[key]

    def _read(self, repo, commit, name):
        if self.from_dir:
            p = subprocess.run(["git", "-C", os.path.join(self.from_dir, repo), "show", "%s:%s" % (commit, name)],
                               capture_output=True, timeout=60)
            if p.returncode != 0:
                raise Drift("%s: %s not readable at %s in %s (%s)" % (repo, name, commit[:7], self.from_dir,
                                                                      p.stderr.decode("utf-8", "replace").strip()[:120]))
            return p.stdout.decode("utf-8")
        url = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (OWNER, repo, commit, name)
        last = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sca-gen-stats"}),
                                            timeout=30) as r:
                    return r.read().decode("utf-8")
            except Exception as e:  # noqa: BLE001 - network is flaky, retry everything
                last = e
                if getattr(e, "code", None) == 404:
                    break
                time.sleep(2 * (attempt + 1))
        raise Drift("%s: could not fetch %s (%s)" % (repo, url, last))


# ---------------------------------------------------------------- quote extraction

def _norm(s):
    return re.sub(r"\s+", " ", s).strip()


def _quote_regex(q):
    parts = q.split("{#}")
    lit = [re.escape(re.sub(r"\s+", " ", p)).replace(r"\ ", r"\s*") for p in parts]
    return re.compile(NUM.join(lit))


def extract(spec, repo, commit, docs, default_doc, field):
    """A quote spec -> int (None for a JSON null)."""
    if spec is None:
        return None
    if isinstance(spec, list):
        vals = [extract(s, repo, commit, docs, default_doc, field) for s in spec]
        return sum(vals)
    fixed = None
    if isinstance(spec, dict):
        fixed, spec = spec["value"], spec["q"]
    doc, q = default_doc, spec
    if "::" in spec:
        doc, q = spec.split("::", 1)
    text = _norm(docs.get(repo, commit, doc))
    if "{#}" not in q:
        if _norm(q) not in text:
            raise Drift("%s %s: quote no longer in %s@%s: %r" % (repo, field, doc, commit[:7], q))
        if fixed is None:
            raise Drift("%s %s: quote without {#} needs a value" % (repo, field))
        return fixed
    m = _quote_regex(q).search(text)
    if not m:
        raise Drift("%s %s: quote no longer in %s@%s: %r" % (repo, field, doc, commit[:7], q))
    if fixed is not None:
        return fixed
    return sum(int(g.replace(",", "")) for g in m.groups())


def _frac(k, n):
    if k is None or n is None:
        return None
    return {"k": k, "n": n, "pct": round(100.0 * k / n, 1) if n else None}


def _kn(spec, split_n, repo, commit, docs, doc, field):
    """before/after: a plain quote (count over split n) or {"k": quote, "n": quote}."""
    if spec is None:
        return None
    if isinstance(spec, dict) and "k" in spec:
        return _frac(extract(spec["k"], repo, commit, docs, doc, field),
                     extract(spec["n"], repo, commit, docs, doc, field))
    return _frac(extract(spec, repo, commit, docs, doc, field), split_n)


# ---------------------------------------------------------------- building the JSON

def _rate(k, n, digits=2):
    if k is None or n is None:
        return None
    return "%d/%d (%.*f%%)" % (k, n, digits, 100.0 * k / n)


def canary_counts():
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import canaries  # noqa: E402  (reads the vendored test tables with ast.literal_eval)
    out = {}
    for eco, _name, kind, *_ in canaries.cases():
        c = out.setdefault(eco, {"malicious": 0, "benign": 0})
        c[kind] += 1
    return out


def build(docs):
    src = json.load(open(SOURCES, encoding="utf-8"))["repos"]
    vers = sca.versions()
    repo_eco = {a["repo"]: eco for eco, a in sca.ADAPTERS.items()}
    counts = canary_counts()
    missing = sorted(set(repo_eco) ^ set(src))
    if missing:
        raise Drift("family_sources.json and sca.ADAPTERS disagree on: %s" % ", ".join(missing))
    errors, repos = [], []
    for repo in sorted(src):
        s = src[repo]
        commit = vers[repo]["commit"]
        eco = repo_eco[repo]
        r = {"repo": repo, "sca_ecosystem": eco, "ecosystem": s["ecosystem"], "runs_at": s["runs_at"]}
        try:
            q = s["quotes"]
            for f in FP_FIELDS:
                r[f] = extract(q.get(f), repo, commit, docs, "FINDINGS.md", f)
            r["heldout_highplus_rate"] = _rate(r["heldout_highplus_count"], r["heldout_n"])
            r["heldout_highplus_fp_rate"] = _rate(r["heldout_highplus_fp_count"], r["heldout_n"])
            for f in sorted(set(q) - set(FP_FIELDS)):
                r[f] = extract(q[f], repo, commit, docs, "FINDINGS.md", f)
            if s.get("recall"):
                r["recall"] = build_recall(s["recall"], repo, commit, docs)
        except Drift as e:
            errors.append(str(e))
            continue
        c = counts.get(eco, {"malicious": 0, "benign": 0})
        r.update({
            "naive_flag_rate": s.get("naive_flag_rate"),
            "canaries_malicious": c["malicious"], "canaries_benign": c["benign"],
            "tests_count": c["malicious"] + c["benign"],
            "notable": s.get("notable") or [],
            "findings_date": s.get("findings_date"),
            "source_notes": s.get("source_notes"),
            "docs_commit": commit,
            "docs_url": "https://github.com/%s/%s/blob/%s/FINDINGS.md" % (OWNER, repo, commit),
        })
        if s.get("display"):
            r["display"] = s["display"]
        repos.append(r)
    if errors:
        raise Drift("\n".join(errors))
    return {"generated_by": "scripts/gen_stats.py", "sources": "scripts/family_sources.json",
            "repos": repos, "totals": totals(repos, counts)}


def build_recall(rs, repo, commit, docs):
    doc = rs.get("report", "RECALL.md")
    ex = lambda spec, field: extract(spec, repo, commit, docs, doc, "recall." + field)  # noqa: E731
    out = {"kind": rs["kind"], "dataset": rs["dataset"], "unit": rs["unit"], "engines": rs.get("engines"),
           "report_url": "https://github.com/%s/%s/blob/%s/%s" % (OWNER, repo, commit, doc),
           "samples": ex(rs.get("samples"), "samples"), "distinct": ex(rs.get("distinct"), "distinct"),
           "splits": []}
    for sp in rs["splits"]:
        n = ex(sp["n"], sp["name"] + ".n")
        d = {"name": sp["name"], "n": n,
             "before": _kn(sp.get("before"), n, repo, commit, docs, doc, "recall.%s.before" % sp["name"]),
             "after": _kn(sp.get("after"), n, repo, commit, docs, doc, "recall.%s.after" % sp["name"]),
             "after_is_blind": bool(sp["after_blind"])}
        if sp.get("note"):
            d["note"] = sp["note"]
        if sp.get("primary"):
            d["primary"] = True
        out["splits"].append(d)
    if rs.get("baseline_all"):
        b = rs["baseline_all"]
        out["baseline_all"] = _frac(ex(b["k"], "baseline_all.k"), ex(b["n"], "baseline_all.n"))
    if rs.get("benign"):
        b = rs["benign"]
        n = ex(b["n"], "benign.n")
        out["benign_recheck"] = {"set": b["set"], "n": n, "highplus_before": ex(b["before"], "benign.before"),
                                 "highplus_after": ex(b["after"], "benign.after")}
        if b.get("note"):
            out["benign_recheck"]["note"] = b["note"]
    return out


def totals(repos, counts):
    pooled = [r for r in repos if None not in (r["heldout_n"], r["heldout_highplus_count"], r["heldout_highplus_fp_count"])]
    n = sum(r["heldout_n"] for r in pooled)
    a = sum(r["heldout_highplus_count"] for r in pooled)
    fp = sum(r["heldout_highplus_fp_count"] for r in pooled)
    recall = [r for r in repos if r.get("recall")]
    return {
        "repos": len(repos),
        "calibration_n": sum(r["calibration_n"] or 0 for r in repos),
        "heldout_n": sum(r["heldout_n"] or 0 for r in repos),
        "pooled_repos": [r["sca_ecosystem"] for r in pooled],
        "pooled_excluded": [r["sca_ecosystem"] for r in repos if r not in pooled],
        "pooled_heldout_n": n,
        "pooled_heldout_highplus_alerts": a,
        "pooled_heldout_highplus_misfires": fp,
        "pooled_alert_rate": _rate(a, n),
        "pooled_misfire_rate": _rate(fp, n),
        "tests_count": sum(r["tests_count"] for r in repos),
        "sca_canary_replay": {"malicious": sum(c["malicious"] for c in counts.values()),
                              "benign": sum(c["benign"] for c in counts.values()),
                              "note": "every scanner's own canaries + benign controls, replayed through sca's "
                                      "adapters by tests/test_canaries.py at the vendored commits"},
        "recall_repos": [r["sca_ecosystem"] for r in recall],
        "notes": "Held-out columns are each repo's blind run with frozen rules; vsix uses its fresh held-out set 3 "
                 "(frozen v0.2.0), the v0.1.0 held-out sets 1+2 are kept as earlier_heldout_*. FP counts follow each "
                 "doc's own label: accurate-but-benign HIGH+ hits are alerts, not misfires. Recall 'after' numbers "
                 "on splits with after_is_blind=false were tuned on those samples and are not recall estimates.",
    }


# ---------------------------------------------------------------- README rendering

def _c(n):
    return "–" if n is None else "{:,}".format(n)


def _pc(k, n):
    if k is None:
        return None
    return "%s (%.2f%%)" % (_c(k), 100.0 * k / n) if n else _c(k)


def _f(fr):
    if not fr:
        return "–"
    return "%d/%d (%s%%)" % (fr["k"], fr["n"], ("%.1f" % fr["pct"]).rstrip("0").rstrip("."))


def render_family(st):
    rows = ["| `sca` key | Scanner | What runs at install / load time | Calibration n | Held-out n | "
            "Held-out HIGH+ alerts | of which misfires (FP) | Canaries / benign controls | Numbers from |",
            "|---|---|---|---:|---:|---:|---:|---:|---|"]
    for r in sorted(st["repos"], key=lambda r: r["sca_ecosystem"]):
        disp = r.get("display", {})
        if r["heldout_n"] is None:
            al = fp = "no held-out split"
        else:
            al = disp.get("alerts") or _pc(r["heldout_highplus_count"], r["heldout_n"]) or "not reported"
            fp = disp.get("misfires") or _pc(r["heldout_highplus_fp_count"], r["heldout_n"]) or "not reported"
        rows.append("| `%s` | [%s](https://github.com/%s/%s) | %s | %s | %s | %s | %s | %d / %d | [`%s`](%s) |" % (
            r["sca_ecosystem"], r["repo"], OWNER, r["repo"], r["runs_at"], _c(r["calibration_n"]), _c(r["heldout_n"]),
            al, fp, r["canaries_malicious"], r["canaries_benign"], r["docs_commit"][:7], r["docs_url"]))
    t = st["totals"]
    exc = ", ".join(t["pooled_excluded"])
    rows += ["", "Pooled over the %d scanners with a held-out split and a reported count (all except %s): "
             "**%s (%.2f%%) HIGH+ alerts and %s (%.2f%%) misfires on %s never-seen popular packages**." % (
                 len(t["pooled_repos"]), exc, _c(t["pooled_heldout_highplus_alerts"]),
                 100.0 * t["pooled_heldout_highplus_alerts"] / t["pooled_heldout_n"],
                 _c(t["pooled_heldout_highplus_misfires"]),
                 100.0 * t["pooled_heldout_highplus_misfires"] / t["pooled_heldout_n"], _c(t["pooled_heldout_n"]))]
    notes = [r for r in st["repos"] if r.get("display", {}).get("note")]
    for r in notes:
        rows += ["", r["display"]["note"]]
    rows += ["", "What the corpora showed, in aggregate (no package is named here):", ""]
    for r in sorted(st["repos"], key=lambda r: r["sca_ecosystem"]):
        if r["notable"]:
            rows.append("- **%s**: %s." % (r["sca_ecosystem"], "; ".join(x.rstrip(".") for x in r["notable"])))
    return "\n".join(rows)


def render_recall(st):
    rec = [r for r in sorted(st["repos"], key=lambda r: r["sca_ecosystem"]) if r.get("recall")]
    head = []
    for r in rec:
        blind = [sp for sp in r["recall"]["splits"] if sp["after_is_blind"]]
        if blind:
            sp = ([b for b in blind if b.get("primary")] or blind)[-1]
            head.append("`%s` %s → **%s**" % (r["sca_ecosystem"], _f(sp["before"]), _f(sp["after"])))
    rows = ["**Blind held-out recall, HIGH+, engine before → frozen rules:** " + "; ".join(head) + ".", "",
            "| `sca` key | Evidence | **Blind: frozen rules on samples they never saw**, HIGH+ before → after | "
            "Tuned on (after = not a recall estimate), HIGH+ before → after | Benign re-check, HIGH+ before → after |",
            "|---|---|---|---|---|"]
    for r in rec:
        rc = r["recall"]
        ev = "%s: %s" % ("real malware" if rc["kind"] == "real-malware" else "incident replay", rc["dataset"])
        if rc.get("samples") is not None or rc.get("distinct") is not None:
            ev += " (%s samples, %s distinct)" % (_c(rc.get("samples")), _c(rc.get("distinct")))
        blind, tuned = [], []
        for sp in rc["splits"]:
            cell = "%s, n=%s: %s → **%s**" % (sp["name"], _c(sp["n"]), _f(sp["before"]), _f(sp["after"])) \
                if sp["after_is_blind"] else "%s, n=%s: %s → %s" % (sp["name"], _c(sp["n"]), _f(sp["before"]), _f(sp["after"]))
            if sp.get("note"):
                cell += " (%s)" % sp["note"]
            (blind if sp["after_is_blind"] else tuned).append(cell)
        if rc.get("baseline_all"):
            blind.insert(0, "all, original rules (fully blind): %s" % _f(rc["baseline_all"]))
        b = rc.get("benign_recheck")
        bc = "–" if not b else "%s → %s of %s (%s)%s" % (_c(b["highplus_before"]), _c(b["highplus_after"]), _c(b["n"]),
                                                         b["set"], "; " + b["note"] if b.get("note") else "")
        rows.append("| `%s` | %s; unit: %s; [report](%s) | %s | %s | %s |" % (
            r["sca_ecosystem"], ev, rc["unit"], rc["report_url"], "<br>".join(blind) or "–", "<br>".join(tuned) or "–", bc))
    rest = [r["sca_ecosystem"] for r in sorted(st["repos"], key=lambda r: r["sca_ecosystem"]) if not r.get("recall")]
    rows += ["", "No real-malware or incident-replay set yet (recall = own canaries only): %s." % ", ".join(
        "`%s`" % e for e in rest)]
    return "\n".join(rows)


def render_canaries(st):
    c = st["totals"]["sca_canary_replay"]
    return ("At the vendored commits: **%d malicious canaries and %d benign controls** across all %d scanners, "
            "every one required to pass." % (c["malicious"], c["benign"], st["totals"]["repos"]))


BLOCKS = {"family-table": render_family, "recall": render_recall, "canary-count": render_canaries}


def render_readme(text, st):
    for name, fn in BLOCKS.items():
        pat = re.compile(r"^([ \t]*)<!-- gen_stats:%s -->.*?<!-- /gen_stats:%s -->" % (name, name), re.S | re.M)
        m = pat.search(text)
        if not m:
            raise Drift("README.md has no <!-- gen_stats:%s --> block" % name)
        ind = m.group(1)
        body = "\n".join((ind + ln) if ln else "" for ln in fn(st).split("\n"))
        block = "%s<!-- gen_stats:%s -->\n%s\n%s<!-- /gen_stats:%s -->" % (ind, name, body, ind, name)
        text = text[:m.start()] + block + text[m.end():]
    return text


def _dump(st):
    return json.dumps(st, indent=1, ensure_ascii=False) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--from", dest="from_dir", help="read docs from local clones DIR/<repo> instead of GitHub")
    ap.add_argument("--check", action="store_true", help="change nothing; exit 1 if an output is stale")
    ap.add_argument("--render-only", action="store_true", help="re-render README from family_stats.json (offline)")
    ap.add_argument("--also-write", action="append", default=[], metavar="PATH", help="also write the JSON here")
    a = ap.parse_args(argv)
    try:
        if a.render_only:
            st = json.load(open(STATS, encoding="utf-8"))
        else:
            if not a.from_dir:
                _ipv4_only()
            st = build(Docs(a.from_dir))
        readme_old = open(README, encoding="utf-8").read()
        readme_new = render_readme(readme_old, st)
    except Drift as e:
        print("gen_stats: DRIFT - fix scripts/family_sources.json against the doc:\n" + str(e), file=sys.stderr)
        return 1
    outs = [(README, readme_old, readme_new)]
    if not a.render_only:
        for p in [STATS] + a.also_write:
            old = open(p, encoding="utf-8").read() if os.path.exists(p) else ""
            outs.append((p, old, _dump(st)))
    stale = [p for p, old, new in outs if old != new]
    if a.check:
        for p in stale:
            print("stale: %s" % os.path.relpath(p, ROOT))
        return 1 if stale else 0
    for p, old, new in outs:
        if old != new:
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(new)
            print("wrote %s" % p)
    if not stale:
        print("up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
