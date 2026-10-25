# [EN] Collect historical rdpwrap.ini blobs from local/external git repositories and report version coverage.
# [KO] 로컬/외부 git 저장소에서 과거 rdpwrap.ini를 수집하고 버전 커버리지를 보고한다.

import csv
import hashlib
import os
import re
import subprocess
import sys
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
HIST = os.path.join(BASE, "history")
COLLECTED = os.path.join(HIST, "_collected")
OUT = os.path.dirname(BASE)

VERSION_RE = re.compile(rb"^\[(\d+)\.(\d+)\.(\d+)\.(\d+)\]\r?$", re.MULTILINE)

REPOS = [
    ("sebaxakerhtc", os.path.join(HIST, "sebaxakerhtc"), "rdpwrap.ini"),
    ("affinityv", os.path.join(HIST, "affinityv"), "rdpwrap.ini"),
    ("jia58628", os.path.join(HIST, "jia58628"), "rdpwrap.ini"),
    ("wangdong15", os.path.join(HIST, "wangdong15"), "rdpwrap.ini"),
    ("stascorp", os.path.join(HIST, "stascorp"), "res/rdpwrap.ini"),
    ("minicom365-local", r"C:\Users\ms338\Documents\deepseek-harness\default-workspace\.malware-scan\publish\fork\rdpwrap", "res/rdpwrap.ini"),
]

LOCAL_FILES = [
    ("system-installed", r"C:\Program Files\RDP Wrapper\rdpwrap.ini"),
    ("system-new", r"C:\Program Files\RDP Wrapper\rdpwrap_new.ini"),
]

TARGET_BUILDS = [8115, 8328, 8521, 8737, 8875, 8972, 9278, 9444, 9549, 9703]


def git(args, cwd, input_bytes=None):
    return subprocess.run(["git"] + args, cwd=cwd, input=input_bytes,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def repo_raw(repo, path):
    """Return list of (commit, date, blob) for the file's history via git log --raw."""
    r = git(["log", "--no-abbrev", "--format=C|%H|%ad", "--date=short", "--raw", "--", path], repo)
    out = []
    cur = None
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("C|"):
            parts = line.split("|")
            if len(parts) >= 3:
                cur = (parts[1], parts[2])
        elif line.startswith(":") and cur:
            # :100644 100644 <old> <new> M\tpath
            head, _, _ = line.partition("\t")
            fields = head.split()
            if len(fields) >= 4:
                blob = fields[3]
                out.append((cur[0], cur[1], blob))
    return out


def fetch_blobs(repo, blobs):
    """Return {blob_sha: content} via one cat-file --batch call."""
    blobs = sorted(set(blobs))
    if not blobs:
        return {}
    inp = "".join(b + "\n" for b in blobs).encode()
    r = git(["cat-file", "--batch"], repo, inp)
    data = r.stdout
    out = {}
    i = 0
    while i < len(data):
        nl = data.find(b"\n", i)
        if nl < 0:
            break
        header = data[i:nl].decode("utf-8", "replace")
        i = nl + 1
        parts = header.split()
        if len(parts) < 3:
            continue
        sha, typ, size = parts[0], parts[1], int(parts[2])
        content = data[i:i + size]
        i += size
        if i < len(data) and data[i:i + 1] == b"\n":
            i += 1
        if typ == "blob":
            out[sha] = content
    return out


def parse_versions(content):
    return {tuple(int(x) for x in m.groups()) for m in VERSION_RE.finditer(content)}


def main():
    os.makedirs(COLLECTED, exist_ok=True)
    commit_rows = []
    version_rows = []
    global_union = set()
    head_union = set()
    head_status = {}
    repo_summary = []

    for name, repo, path in REPOS:
        if not os.path.isdir(os.path.join(repo, ".git")):
            print("skip %s (not cloned)" % name)
            continue
        raw = repo_raw(repo, path)
        blobs = fetch_blobs(repo, [b for _, _, b in raw])
        outdir = os.path.join(COLLECTED, name)
        os.makedirs(outdir, exist_ok=True)
        seen = set()
        counts = {}
        versions_for_repo = set()
        dates = []
        for sha, date, blob in raw:
            if blob in seen or blob not in blobs:
                continue
            seen.add(blob)
            content = blobs[blob]
            digest = hashlib.sha256(content).hexdigest()
            fn = os.path.join(outdir, digest[:16] + ".ini")
            if not os.path.exists(fn):
                with open(fn, "wb") as f:
                    f.write(content)
            vs = parse_versions(content)
            latest = max(vs) if vs else None
            versions_for_repo |= vs
            dates.append(date)
            commit_rows.append({
                "repo": name, "commit": sha, "commit_date": date,
                "blob": blob, "sha256": digest, "size": len(content),
                "versions": len(vs), "latest_version": ".".join(map(str, latest)) if latest else "",
                "file": os.path.basename(fn),
            })
            for v in vs:
                counts.setdefault(v, []).append(date)
        for v, ds in counts.items():
            version_rows.append({
                "repo": name, "version": ".".join(map(str, v)),
                "first_date": min(ds), "last_date": max(ds),
                "seen_commits": len(ds),
            })
        global_union |= versions_for_repo
        head_content = git(["show", "HEAD:%s" % path], repo).stdout
        head_vs = parse_versions(head_content)
        head_union |= head_vs
        head_status[name] = head_vs
        if head_content:
            with open(os.path.join(outdir, "HEAD.ini"), "wb") as f:
                f.write(head_content)
        repo_summary.append({
            "repo": name, "commits": len(raw), "unique_inis": len(seen),
            "first_date": min(dates) if dates else "",
            "last_date": max(dates) if dates else "",
            "versions": len(versions_for_repo),
            "latest_version": ".".join(map(str, max(versions_for_repo))) if versions_for_repo else "",
            "head_versions": len(head_vs),
            "head_latest": ".".join(map(str, max(head_vs))) if head_vs else "",
            "head_26100": len([v for v in head_vs if v[:3] == (10, 0, 26100)]),
        })

    for name, fn in LOCAL_FILES:
        if not os.path.exists(fn):
            continue
        with open(fn, "rb") as f:
            content = f.read()
        vs = parse_versions(content)
        latest = max(vs) if vs else None
        global_union |= vs
        head_union |= vs
        head_status[name] = vs
        digest = hashlib.sha256(content).hexdigest()
        commit_rows.append({
            "repo": name, "commit": "-",
            "commit_date": datetime.fromtimestamp(os.path.getmtime(fn)).strftime("%Y-%m-%d"),
            "blob": "-", "sha256": digest, "size": len(content),
            "versions": len(vs), "latest_version": ".".join(map(str, latest)) if latest else "",
            "file": fn,
        })
        repo_summary.append({
            "repo": name, "commits": 0, "unique_inis": 1,
            "first_date": "", "last_date": "", "versions": len(vs),
            "latest_version": ".".join(map(str, latest)) if latest else "",
            "head_versions": len(vs),
            "head_latest": ".".join(map(str, latest)) if latest else "",
            "head_26100": len([v for v in vs if v[:3] == (10, 0, 26100)]),
        })
        for v in vs:
            version_rows.append({"repo": name, "version": ".".join(map(str, v)),
                                 "first_date": "", "last_date": "", "seen_commits": 1})

    with open(os.path.join(OUT, "coverage_commits.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["repo", "commit", "commit_date", "blob", "sha256", "size", "versions", "latest_version", "file"])
        w.writeheader(); w.writerows(commit_rows)
    with open(os.path.join(OUT, "coverage_versions.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["repo", "version", "first_date", "last_date", "seen_commits"])
        w.writeheader(); w.writerows(version_rows)
    with open(os.path.join(OUT, "coverage_repos.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["repo", "commits", "unique_inis", "first_date", "last_date", "versions", "latest_version", "head_versions", "head_latest", "head_26100"])
        w.writeheader(); w.writerows(sorted(repo_summary, key=lambda x: x["repo"]))

    union_sorted = sorted(global_union)
    head_sorted = sorted(head_union)
    with open(os.path.join(OUT, "versions_union.txt"), "w", encoding="utf-8", newline="\n") as f:
        for v in union_sorted:
            f.write(".".join(map(str, v)) + "\n")

    only26100 = [v for v in union_sorted if v[:3] == (10, 0, 26100)]
    head26100 = [v for v in head_sorted if v[:3] == (10, 0, 26100)]
    target_status = []
    for b in TARGET_BUILDS:
        ver = (10, 0, 26100, b)
        head_repos = sorted(r for r, vs in head_status.items() if ver in vs)
        hist_repos = sorted({r["repo"] for r in version_rows if r["version"] == "10.0.26100.%d" % b})
        target_status.append((b, head_repos, hist_repos))

    lines = ["# rdpwrap.ini 과거 버전 수집·커버리지 리포트", ""]
    lines.append("생성: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("")
    lines.append("## 저장소별 요약")
    lines.append("")
    lines.append("| 저장소 | 커밋 | 고유 INI | 기간 | 과거 합집합 버전 | HEAD 버전 | HEAD 최신 | HEAD 26100 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in sorted(repo_summary, key=lambda x: x["repo"]):
        lines.append("| %s | %d | %d | %s ~ %s | %d | %d | %s | %d |" % (
            r["repo"], r["commits"], r["unique_inis"], r["first_date"], r["last_date"],
            r["versions"], r["head_versions"], r["head_latest"], r["head_26100"]))
    lines.append("")
    lines.append("## 전체 합집합")
    lines.append("")
    lines.append("- 수집된 고유 INI: %d" % len(commit_rows))
    lines.append("- 과거 전체(HEAD 제외 포함) 지원 버전: %d, 최신 %s" % (
        len(union_sorted), ".".join(map(str, union_sorted[-1])) if union_sorted else "-"))
    lines.append("- 현재 HEAD 합집합 지원 버전: %d, 최신 %s" % (
        len(head_sorted), ".".join(map(str, head_sorted[-1])) if head_sorted else "-"))
    lines.append("- 26100 계열: 과거 %d개 / HEAD %d개" % (len(only26100), len(head26100)))
    lines.append("")
    lines.append("## 주요 26100 빌드 포함 여부")
    lines.append("")
    lines.append("| 빌드 | HEAD 포함 저장소 | 과거(HEAD 제외 포함) |")
    lines.append("|---|---|---|")
    for b, head_repos, hist_repos in target_status:
        lines.append("| 26100.%d | %s | %s |" % (
            b, ", ".join(head_repos) if head_repos else "없음", ", ".join(hist_repos) if hist_repos else "없음"))
    lines.append("")
    hist_only = sorted(set(v for v in union_sorted if v not in head_union and v[:3] == (10, 0, 26100)), key=lambda x: x[3])
    if hist_only:
        lines.append("### HEAD에서 제거된(과거에만 존재) 26100 빌드")
        lines.append("")
        for v in hist_only:
            repos = sorted({r["repo"] for r in version_rows if r["version"] == ".".join(map(str, v))})
            lines.append("- 26100.%d: %s" % (v[3], ", ".join(repos)))
        lines.append("")
    lines.append("## 산출물")
    lines.append("")
    lines.append("- `history/_collected/<repo>/*.ini` : 고유 INI 원본 (HEAD.ini 포함)")
    lines.append("- `coverage_commits.csv` : 커밋별 INI 메타데이터")
    lines.append("- `coverage_versions.csv` : 버전별 최초/최종 등장일")
    lines.append("- `coverage_repos.csv` : 저장소별 요약")
    lines.append("- `versions_union.txt` : 전체 버전 목록")
    with open(os.path.join(OUT, "coverage_summary.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    print("collected unique INIs:", len(commit_rows))
    print("union versions:", len(union_sorted), "head union:", len(head_sorted))
    print("latest (hist):", ".".join(map(str, union_sorted[-1])) if union_sorted else "-")
    print("latest (head):", ".".join(map(str, head_sorted[-1])) if head_sorted else "-")
    print("26100 versions: hist=%d head=%d" % (len(only26100), len(head26100)))
    for r in sorted(repo_summary, key=lambda x: x["repo"]):
        print("  %-18s commits=%-4d inis=%-4d head=%-4d head_latest=%s" % (
            r["repo"], r["commits"], r["unique_inis"], r["head_versions"], r["head_latest"]))
    for b, head_repos, hist_repos in target_status:
        print("  26100.%-5d HEAD=[%s] hist=[%s]" % (b, ", ".join(head_repos), ", ".join(hist_repos)))

    return 0


if __name__ == "__main__":
    sys.exit(main())
