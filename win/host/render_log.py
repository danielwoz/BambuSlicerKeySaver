#!/usr/bin/env python3
"""
render_log.py -- turn the genuine networking plugin's decrypted debug log into
readable text. Pairs with declog.exe (which AES-128-ECB-decrypts a
debug_network_*.log.enc). The decrypted records are numeric:

    [ts] [I] [T tid]: \\x1f<id>\\x1f<param1>\\x1f<param2>...

where <id> is the source line number and the human format string ("get_app_cert
error = {}, body = {}, status = {}") lives in the plugin's .rdata. This tool maps
<id> -> format string and fills the params.

Build the id->string map ONCE from a `bambu_host --dump-regions` snapshot of the
same plugin version, then render any decrypted log with it:

    python render_log.py build-map <dump_dir> plugin_logmap.tsv
    declog debug_network_*.log.enc > net.dec
    python render_log.py net.dec [plugin_logmap.tsv]   # default: map beside this script

Pure Python 3 standard library. The map is plugin-version-specific; regenerate it
with build-map if you update the plugin.
"""
import os, re, glob, struct, sys

def build_map(dump_dir):
    regions = []
    for f in glob.glob(os.path.join(dump_dir, "img_*.bin")):
        m = re.match(r"img_([0-9a-f]+)_[0-9a-f]+_(\w+)\.bin", os.path.basename(f))
        if m: regions.append((int(m.group(1), 16), open(f, "rb").read(), m.group(2)))
    regions.sort()
    def read_rva(rva, n):
        for b, d, _ in regions:
            if b <= rva < b + len(d): return d[rva-b:rva-b+n]
        return None
    def cstr(rva):
        d = read_rva(rva, 200)
        if not d: return None
        s = d.split(b"\0")[0]
        try: return s.decode("utf-8")
        except UnicodeDecodeError: return s.decode("latin1", "replace")
    idmap = {}
    for base, d, prot in regions:
        if "X" not in prot: continue
        n = len(d); i = 0
        while i < n - 6:
            # mov dword [rbp+off], imm32  ->  C7 85 <off32> <imm32>  or  C7 45 <off8> <imm32>
            if d[i] == 0xC7 and d[i+1] == 0x85: off_len = 4
            elif d[i] == 0xC7 and d[i+1] == 0x45: off_len = 1
            else: i += 1; continue
            ip = i + 2 + off_len
            if ip + 4 > n: break
            imm = struct.unpack_from("<I", d, ip)[0]
            if 1 <= imm <= 20000:
                for j in range(ip + 4, min(ip + 44, n - 6)):
                    if d[j] == 0x48 and d[j+1] == 0x8D and d[j+2] == 0x15:   # lea rdx,[rip+disp]
                        disp = struct.unpack_from("<i", d, j+3)[0]
                        s = cstr(base + j + 7 + disp)
                        if s and len(s) >= 3 and all(32 <= ord(c) < 127 or c == "\t" for c in s[:40]):
                            idmap.setdefault(imm, s)
                        break
            i = ip + 4
    return idmap

def load_map(path):
    m = {}
    for line in open(path, encoding="utf-8"):
        parts = line.rstrip("\n").split("\t", 1)
        if len(parts) == 2 and parts[0].isdigit(): m[int(parts[0])] = parts[1]
    return m

def render(logpath, idmap):
    data = open(logpath, "rb").read()
    rec = re.compile(rb"\]:\s*\x1f(\d+)((?:\x1f[^\x1f\r\n]*)*)")
    for line in re.split(rb"\r?\n", data):
        m = rec.search(line)
        if not m: continue
        i = int(m.group(1)); fmt = idmap.get(i)
        if not fmt: continue
        out = fmt
        for p in (p.decode("latin1", "replace") for p in m.group(2).split(b"\x1f") if p):
            out = out.replace("{}", p, 1)
        print(f"{line[:31].decode('latin1','replace')} [{i}] {out}")

def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "build-map":
        idmap = build_map(sys.argv[2])
        with open(sys.argv[3], "w", encoding="utf-8") as f:
            for i in sorted(idmap): f.write(f"{i}\t{idmap[i]}\n")
        print(f"wrote {len(idmap)} id->string entries -> {sys.argv[3]}")
        return 0
    if len(sys.argv) >= 2:
        mp = sys.argv[2] if len(sys.argv) >= 3 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin_logmap.tsv")
        if not os.path.exists(mp):
            print(f"map not found: {mp}\nbuild it: python render_log.py build-map <dump_dir> {mp}"); return 1
        render(sys.argv[1], load_map(mp)); return 0
    print(__doc__); return 2

if __name__ == "__main__":
    sys.exit(main())
