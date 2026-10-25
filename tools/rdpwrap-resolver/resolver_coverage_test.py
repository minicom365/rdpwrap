# [EN] Measure rdpwrap_resolver coverage against real termsrv.dll builds from Microsoft's symbol server.
# [KO] Microsoft 심볼 서버의 실제 termsrv.dll 빌드로 리졸버 커버리지를 측정한다.

import csv
import gzip
import hashlib
import json
import os
import re
import sys
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
HIST = os.path.join(BASE, "history")
DLLDIR = os.path.join(HIST, "_dll")
WINB = os.path.join(os.path.dirname(BASE), "winbindex", "termsrv.json.gz")
OUT = os.path.dirname(BASE)
INI_OUT = os.path.join(OUT, "resolver_coverage.csv")

sys.path.insert(0, BASE)
import rdpwrap_resolver as rw  # noqa: E402

VERSION_PREFIXES = {
    "26100": [7705, 7824, 7920, 8115, 8328, 8521, 8737, 8972, 9278, 9444, 9549],
    "28000": None,
}
OLDER_PREFIXES = ["22621", "19041", "17763", "22000", "18362"]

INI_FILES = [
    ("system", r"C:\Program Files\RDP Wrapper\rdpwrap.ini"),
    ("seba-head", os.path.join(HIST, "sebaxakerhtc", "rdpwrap.ini")),
    ("jia-head", os.path.join(HIST, "jia58628", "rdpwrap.ini")),
    ("affinity-head", os.path.join(HIST, "affinityv", "rdpwrap.ini")),
    ("local-fork", r"C:\Users\ms338\Documents\deepseek-harness\default-workspace\.malware-scan\publish\fork\rdpwrap\res\rdpwrap.ini"),
]


def load_expected():
    expected = {}
    for src, path in INI_FILES:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        for m in re.finditer(r"^\[(\d+\.\d+\.\d+\.\d+)\]\r?$", text, re.M):
            ver = m.group(1)
            body = rw.parse_ini_sections(text, "[%s]" % ver) or {}
            offs = {k: body[k] for k in ("LocalOnlyOffset.x64", "SingleUserOffset.x64",
                                         "DefPolicyOffset.x64", "SLInitOffset.x64") if k in body}
            sl = rw.parse_ini_sections(text, "[%s-SLInit]" % ver) or {}
            expected.setdefault(ver, []).append({"source": src, "offsets": offs, "slinit": sl})
    return expected


def download(entry, outdir):
    fi = entry["fileInfo"]
    ts = fi["timestamp"]
    vsize = fi["virtualSize"]
    file_id = "%08X%x" % (ts, vsize)
    url = "https://msdl.microsoft.com/download/symbols/termsrv.dll/%s/termsrv.dll" % file_id
    path = os.path.join(outdir, "%s.dll" % entry["label"])
    if os.path.exists(path) and os.path.getsize(path) > 100000:
        return path
    req = urllib.request.Request(url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})
    with urllib.request.urlopen(req, timeout=180) as r:
        data = r.read()
    with open(path, "wb") as f:
        f.write(data)
    return path


def compare_to_source(version, offsets, slinit, exp, alt_su=None):
    if not all(k in exp["offsets"] for k in ("LocalOnlyOffset.x64", "SingleUserOffset.x64",
                                             "DefPolicyOffset.x64", "SLInitOffset.x64")):
        return None  # incomplete INI section, not comparable
    problems = []
    for key, val in (("LocalOnlyOffset.x64", offsets["LocalOnly"]),
                     ("SingleUserOffset.x64", offsets["SingleUser"]),
                     ("DefPolicyOffset.x64", offsets["DefPolicy"]),
                     ("SLInitOffset.x64", offsets["SLInit"])):
        if exp["offsets"][key].upper() != ("%X" % val).upper():
            if key == "SingleUserOffset.x64" and alt_su and exp["offsets"][key].upper() in alt_su:
                continue  # alternative valid SingleUser patch site
            problems.append("%s exp=%s got=%X" % (key, exp["offsets"][key], val))
    for name, _ in rw.SLINIT_LAYOUT:
        k = name + ".x64"
        if exp["slinit"].get(k) and exp["slinit"][k].upper() != ("%X" % slinit[name]).upper():
            problems.append("%s exp=%s got=%X" % (k, exp["slinit"][k], slinit[name]))
    return problems


def main():
    os.makedirs(DLLDIR, exist_ok=True)
    with gzip.open(WINB, "rt", encoding="utf-8") as f:
        winb = json.load(f)
    entries = []
    for k, v in winb.items():
        fi = v.get("fileInfo", {})
        ver = fi.get("version", "") or ""
        if fi.get("machineType") != 34404:
            continue
        m = re.match(r"10\.0\.(\d+)\.(\d+)", ver)
        if not m:
            continue
        prefix, build = m.group(1), int(m.group(2))
        want = False
        if prefix in VERSION_PREFIXES:
            builds = VERSION_PREFIXES[prefix]
            want = bool(builds is None or build in builds)
        elif prefix in OLDER_PREFIXES:
            want = True
        if want:
            entries.append({"label": "%s.%s" % (prefix, build), "version": ver.split(" ")[0],
                            "fileInfo": fi, "sha256": fi.get("sha256", ""), "prefix": prefix, "build": build})
    by_prefix = {}
    for e in entries:
        if e["prefix"] in OLDER_PREFIXES:
            by_prefix.setdefault(e["prefix"], []).append(e)
    for p, lst in by_prefix.items():
        lst.sort(key=lambda x: x["build"])
        entries = [e for e in entries if e["prefix"] != p] + [lst[-1]]

    expected = load_expected()
    rows = []
    for e in entries:
        row = {"label": e["label"], "version": e["version"], "sha256": e["sha256"],
               "download": "", "resolver": "", "ini_compare": "", "detail": ""}
        try:
            path = download(e, DLLDIR)
            with open(path, "rb") as f:
                data = f.read()
            digest = hashlib.sha256(data).hexdigest()
            row["download"] = "OK" if digest.lower() == e["sha256"].lower() else "HASH_MISMATCH"
            if row["download"] != "OK":
                rows.append(row)
                continue
            pe, version, offsets, codes, slinit = rw.derive(path)
            alt_su = set()
            for var in rw.ANCHORS["SingleUser"]:
                hits = rw.find_all(pe, var["pattern"])
                if len(hits) == 1:
                    alt_su.add("%X" % hits[0])
            row["resolver"] = "OK (%s/%s)" % (codes.get("SingleUser"), codes.get("DefPolicy"))
        except Exception as ex:
            row["resolver"] = "FAIL: %s" % ex
            rows.append(row)
            continue
        sources = expected.get(e["version"], [])
        results = []
        for exp in sources:
            problems = compare_to_source(e["version"], offsets, slinit, exp, alt_su)
            if problems is None:
                continue
            results.append((exp["source"], problems))
        if not results:
            row["ini_compare"] = "NO_COMPLETE_INI"
        elif any(not p for _, p in results):
            row["ini_compare"] = "MATCH (%s)" % ", ".join(s for s, p in results if not p)
        else:
            row["ini_compare"] = "MISMATCH"
            row["detail"] = " | ".join("%s: %s" % (s, "; ".join(p)) for s, p in results)
        rows.append(row)

    with open(INI_OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label", "version", "sha256", "download", "resolver", "ini_compare", "detail"])
        w.writeheader(); w.writerows(rows)

    print("%-14s %-22s %-13s %-42s %s" % ("label", "version", "dl", "resolver", "ini"))
    for r in rows:
        print("%-14s %-22s %-13s %-42s %s" % (r["label"], r["version"], r["download"], r["resolver"], r["ini_compare"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())


