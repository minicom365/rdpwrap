# [EN] Deterministic RDP Wrapper INI section generator from a termsrv.dll build.
# [KO] termsrv.dll 빌드에서 RDP Wrapper INI 섹션을 결정론적으로 생성하는 도구.
#
# Goal / 목적:
#   - Remove dependence on externally hosted rdpwrap.ini offset updates.
#   - 외부에서 배포되는 rdpwrap.ini 오프셋 갱신에 대한 의존을 제거한다.
#   - Patch sites are located by version-scoped byte anchors; ambiguity fails closed.
#   - 패치 지점은 버전 범위별 바이트 앵커로 찾고, 모호하면 fail-closed.
#
# Usage / 사용:
#   python rdpwrap_resolver.py --dll <termsrv.dll> [--ini <rdpwrap.ini>] [--verify] [--emit] [--out out.ini]

import argparse
import hashlib
import os
import re
import shutil
import struct
import sys
from datetime import datetime

# [EN] Byte anchors. min/max are inclusive version tuples; omitted means any version.
# [KO] 바이트 앵커. min/max는 포함 범위이며 생략 시 모든 버전.
ANCHORS = {
    "LocalOnly": [
        {
            "pattern": [0x74, 0x44, 0x83, 0x3D, None, None, None, None, 0x02,
                        0xBB, 0x05, 0x00, 0x07, 0x80, 0x0F, 0x86, 0xC9, 0x00, 0x00, 0x00,
                        0x48, 0x8D, 0x05],
            "code": "jmpshort",
        },
    ],
    "SingleUser": [
        {
            # 10.0.26100.8737+ and 10.0.28000.x: call + test + jz shape
            "pattern": [0x48, 0xFF, 0x15, None, None, None, None, 0x0F, 0x1F, 0x44, 0x00, 0x00,
                        0x85, 0xC0, 0x0F, 0x84, 0x88, 0x01, 0x00, 0x00,
                        0x41, 0xB9, 0x19, 0x00, 0x02, 0x00, 0x4C, 0x8D, 0x05],
            "code": "mov_eax_1_nop_2",
        },
        {
            # 10.0.26100.7824..8521 (and 26200.x): direct immediate shape
            "pattern": [0x01, 0x00, 0x00, 0x00, 0x41, 0xB0, 0x07, 0x66, 0x89, 0x85, 0xA8, 0x00,
                        0x00, 0x00, 0x8D, 0x57, 0x40, 0xC7, 0x45, 0x90, 0x1C, 0x01, 0x00, 0x00],
            "code": "Zero",
        },
    ],
    "DefPolicy": [
        {
            # 10.0.26100.8521+ (and 28000.2336+): mov r9d,[rdi+0x638] / cmp / jne shape
            "pattern": [0x44, 0x8B, 0x8F, 0x38, 0x06, 0x00, 0x00, 0x45, 0x3B, 0xC1, 0x75],
            "code": "CDefPolicy_Query_r9d_rdi_jmp",
        },
        {
            # 10.0.26100.7824..8328 (and 26200.x / 28000.2179): mov eax,[rcx+0x638] / cmp shape
            "pattern": [0x8B, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x75, 0x16],
            "code": "CDefPolicy_Query_eax_rcx_jmp",
        },
        {
            # 10.0.28000.2336+: mov r9d,[rdi+0x63C] / cmp / jne shape
            "pattern": [0x44, 0x8B, 0x87, 0x3C, 0x06, 0x00, 0x00, 0x45, 0x3B, 0xC1, 0x75],
            "code": "CDefPolicy_Query_r9d_rdi_jmp",
        },
    ],
    "SLInit": [
        {
            "pattern": [0x40, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x05, 0x00, 0x00, 0x48, 0x8B, 0x05],
            "code": None,
        },
    ],
}

SLINIT_LAYOUT = [
    ("bInitialized", 0x00),
    ("bServerSku", 0x04),
    ("lMaxUserSessions", 0x08),
    ("bAppServerAllowed", 0x10),
    ("bRemoteConnAllowed", 0x1C),
    ("bMultimonAllowed", 0x20),
    ("ulMaxDebugSessions", 0x28),
    ("bFUSEnabled", 0x2C),
]
CLUSTER_PROBES = [0x04, 0x08, 0x10, 0x1C, 0x20, 0x2C]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


class PEImage:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.b = f.read()
        b = self.b
        e = u32(b, 0x3C)
        if b[e:e + 4] != b"PE\0\0":
            raise ValueError("not a PE image")
        self.num_sections = u16(b, e + 6)
        self.opt_size = u16(b, e + 20)
        opt = e + 24
        self.magic = u16(b, opt)
        self.is_pe32plus = self.magic == 0x20B
        self.image_base = u64(b, opt + 24) if self.is_pe32plus else u32(b, opt + 28)
        self.size_image = u32(b, opt + 56)
        self.sections = []
        sec = opt + self.opt_size
        for i in range(self.num_sections):
            o = sec + i * 40
            name = b[o:o + 8].rstrip(b"\0").decode("latin1")
            self.sections.append({
                "name": name, "vsize": u32(b, o + 8), "vaddr": u32(b, o + 12),
                "rsize": u32(b, o + 16), "raddr": u32(b, o + 20),
            })

    def rva_to_off(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
                return s["raddr"] + (rva - s["vaddr"])
        return None

    def off_to_rva(self, off):
        for s in self.sections:
            if s["raddr"] <= off < s["raddr"] + s["rsize"]:
                return s["vaddr"] + (off - s["raddr"])
        return None

    def fixed_version(self):
        sig = struct.pack("<I", 0xFEEF04BD)
        i = self.b.find(sig)
        while i != -1:
            if i + 0x10 <= len(self.b):
                ms = u32(self.b, i + 8)
                ls = u32(self.b, i + 12)
                return (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
            i = self.b.find(sig, i + 1)
        return None


def find_all(pe, pattern):
    b = pe.b
    out = []
    i = 0
    first = pattern[0]
    while True:
        i = b.find(bytes([first]), i)
        if i < 0:
            break
        ok = True
        for k, p in enumerate(pattern):
            if p is not None and b[i + k] != p:
                ok = False
                break
        if ok:
            out.append(i)
        i += 1
    return out


def resolve_site(pe, variants, version, label):
    """Return the first anchor variant that matches exactly once.

    Several variants can be valid alternative patch sites for the same function
    (e.g. SingleUser Zero and mov_eax variants); ANCHORS priority decides order.
    """
    detail = []
    for v in variants:
        hits = find_all(pe, v["pattern"])
        detail.append("%d hit(s)" % len(hits))
        if len(hits) == 1:
            return hits[0], v
    raise ValueError("%s: no unique anchor (%s)" % (label, ", ".join(detail)))


def scan_global_stores(pe, fn_off, limit=0x1000):
    b = pe.b
    end = min(fn_off + limit, len(b))
    out = []
    i = fn_off
    while i < end - 10:
        nxt = pe.off_to_rva(i)
        if nxt is None:
            i += 1
            continue
        j = i
        if 0x40 <= b[j] <= 0x4F:
            j += 1
        if j + 1 >= len(b):
            break
        op = b[j]
        if b[j + 1] == 0x05 and op in (0x88, 0x89, 0xC6, 0xC7):
            if op in (0x88, 0x89):
                length = (j - i) + 6
                width = 1 if op == 0x88 else 4
            elif op == 0xC6:
                length = (j - i) + 7
                width = 1
            else:
                length = (j - i) + 10
                width = 4
            disp = struct.unpack_from("<i", b, j + 2)[0]
            out.append((nxt + length + disp, width))
            i += length
            continue
        i += 1
    return out


def derive_slinit(pe, slinit_off):
    stores = scan_global_stores(pe, slinit_off)
    targets = sorted({t for (t, w) in stores})
    tset = set(targets)
    candidates = set()
    for t in targets:
        for d in CLUSTER_PROBES:
            candidates.add(t - d)
    bases = sorted(b for b in candidates if all((b + d) in tset for d in CLUSTER_PROBES))
    if len(bases) != 1:
        raise ValueError("SLInit cluster base ambiguous: %s" % [hex(x) for x in bases])
    base = bases[0]
    return base, {name: base + rel for name, rel in SLINIT_LAYOUT}


def parse_ini_sections(ini_text, header):
    lines = ini_text.splitlines()
    try:
        start = lines.index(header)
    except ValueError:
        return None
    out = {}
    for line in lines[start + 1:]:
        s = line.strip()
        if s.startswith("["):
            break
        if not s or s.startswith(";"):
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def build_section(version, offsets, codes, slinit):
    ver = "%d.%d.%d.%d" % version
    lines = ["[%s]" % ver, "; generated deterministically by rdpwrap_resolver.py", ""]
    for label in ("LocalOnly", "SingleUser", "DefPolicy", "SLInit"):
        patch = {"LocalOnly": "LocalOnlyPatch", "SingleUser": "SingleUserPatch",
                 "DefPolicy": "DefPolicyPatch", "SLInit": "SLInitHook"}[label]
        offkey = {"LocalOnly": "LocalOnlyOffset", "SingleUser": "SingleUserOffset",
                  "DefPolicy": "DefPolicyOffset", "SLInit": "SLInitOffset"}[label]
        lines.append("%-22s=1" % (patch + ".x64"))
        lines.append("%-22s=%X" % (offkey + ".x64", offsets[label]))
        if codes.get(label):
            ckey = {"LocalOnly": "LocalOnlyCode", "SingleUser": "SingleUserCode",
                    "DefPolicy": "DefPolicyCode", "SLInit": None}[label]
            lines.append("%-22s=%s" % (ckey + ".x64", codes[label]))
    lines.append("%-22s=New_CSLQuery_Initialize" % "SLInitFunc.x64")
    lines.append("")
    lines.append("[%s-SLInit]" % ver)
    lines.append("; generated deterministically by rdpwrap_resolver.py")
    for name, _ in SLINIT_LAYOUT:
        lines.append("%-22s=%X" % (name + ".x64", slinit[name]))
    return "\n".join(lines) + "\n"


def verify_against_ini(version, offsets, slinit, ini_path):
    with open(ini_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    ver = "%d.%d.%d.%d" % version
    sec = parse_ini_sections(text, "[%s]" % ver)
    if sec is None:
        return False, ["section [%s] not found" % ver]
    problems = []
    for label, key in (("LocalOnly", "LocalOnlyOffset.x64"), ("SingleUser", "SingleUserOffset.x64"),
                       ("DefPolicy", "DefPolicyOffset.x64"), ("SLInit", "SLInitOffset.x64")):
        want = "%X" % offsets[label]
        got = sec.get(key)
        if got is None:
            problems.append("missing %s" % key)
        elif got.upper() != want.upper():
            problems.append("%s expected %s got %s" % (key, want, got))
    sl = parse_ini_sections(text, "[%s-SLInit]" % ver)
    if sl is None:
        problems.append("SLInit section not found")
    else:
        for name, _ in SLINIT_LAYOUT:
            key = name + ".x64"
            got = sl.get(key)
            if got is not None and got.upper() != ("%X" % slinit[name]).upper():
                problems.append("%s expected %s got %s" % (key, "%X" % slinit[name], got))
    return (len(problems) == 0), problems


def _split_generated(section_text):
    lines = section_text.splitlines()
    out = []
    cur = None
    for line in lines:
        if line.startswith("[") and line.endswith("]"):
            if cur:
                out.append(cur)
            cur = [line, []]
        elif cur:
            cur[1].append(line)
    if cur:
        out.append(cur)
    return [(h, body) for h, body in out]


def _replace_section(lines, header, body):
    try:
        start = lines.index(header)
    except ValueError:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(header)
        lines.extend(body)
        return
    end = start + 1
    while end < len(lines) and not lines[end].startswith("["):
        end += 1
    lines[start:end] = [header] + body


def apply_section(ini_path, section_text):
    with open(ini_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        text = f.read()
    nl = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    for header, body in _split_generated(section_text.replace("\r\n", "\n")):
        _replace_section(lines, header, body)
    new_text = nl.join(lines) + nl
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = "%s.bak-%s" % (ini_path, stamp)
    shutil.copy2(ini_path, backup)
    tmp = ini_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(new_text)
    os.replace(tmp, ini_path)
    return backup


def derive(dll_path):
    pe = PEImage(dll_path)
    version = pe.fixed_version()
    if version is None:
        raise ValueError("VS_FIXEDFILEINFO not found")
    offsets = {}
    codes = {}
    for label, variants in ANCHORS.items():
        off, variant = resolve_site(pe, variants, version, label)
        offsets[label] = off
        codes[label] = variant.get("code")
    _, slinit = derive_slinit(pe, offsets["SLInit"])
    return pe, version, offsets, codes, slinit


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deterministic rdpwrap.ini generator")
    ap.add_argument("--dll", required=True, help="termsrv.dll path")
    ap.add_argument("--ini", help="rdpwrap.ini path for verification/apply")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    try:
        pe, version, offsets, codes, slinit = derive(args.dll)
    except (ValueError, OSError) as ex:
        print("ERROR: %s" % ex, file=sys.stderr)
        return 3

    ver = "%d.%d.%d.%d" % version
    print("termsrv.dll : %s" % os.path.basename(args.dll))
    print("sha256      : %s" % hashlib.sha256(pe.b).hexdigest())
    print("version     : %s" % ver)
    for label in ("LocalOnly", "SingleUser", "DefPolicy", "SLInit"):
        print("  %-10s offset = 0x%X  code = %s" % (label, offsets[label], codes.get(label)))
    for name, _ in SLINIT_LAYOUT:
        print("    %-20s = 0x%X" % (name, slinit[name]))

    if args.verify:
        if not args.ini:
            print("ERROR: --verify requires --ini", file=sys.stderr)
            return 2
        ok, problems = verify_against_ini(version, offsets, slinit, args.ini)
        print("verify      : %s" % ("MATCH" if ok else "MISMATCH"))
        for p in problems:
            print("  - %s" % p)
        if not ok:
            return 4

    if args.emit or args.out:
        section = build_section(version, offsets, codes, slinit)
        if args.emit:
            print("")
            print(section)
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(section)
            print("written: %s" % args.out)

    if args.apply:
        if not args.ini:
            print("ERROR: --apply requires --ini", file=sys.stderr)
            return 2
        section = build_section(version, offsets, codes, slinit)
        backup = apply_section(args.ini, section)
        ok, problems = verify_against_ini(version, offsets, slinit, args.ini)
        print("apply       : %s (backup: %s)" % ("OK" if ok else "MISMATCH", backup))
        for p in problems:
            print("  - %s" % p)
        if not ok:
            return 5

    return 0


if __name__ == "__main__":
    sys.exit(main())

