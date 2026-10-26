#!/usr/bin/env python3
"""Build the thesis tables from the raw `go test -bench` logs in bench_out/.

    python scripts/thesis_tables.py [bench_out] [--ghz 3.8]

Every cell is the MEDIAN over all repetitions found in the logs. Output is
printed and also written to <bench_out>/thesis_tables.md (UTF-8).

Ratios ("Ti le"):
  * time tables (3.4, 3.6, 3.7, permutation): Keccak-256 / K12-SBox
  * rate tables (3.5 tx/s, throughput):       K12-SBox / Keccak-256
  so a value > 1 always means "K12-SBox is better".
--ghz F adds cycles/byte columns computed as ns/byte * F (F = TSC / base
clock in GHz). Omit it if you do not want c/b.
"""
import os
import re
import statistics
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LINE = re.compile(r"^Benchmark(\S+?)-\d+\s+\d+\s+([\d.]+) ns/op(.*)$")
MBS = re.compile(r"([\d.]+) MB/s")
HASH_NS = re.compile(r"([\d.]+) hash-ns/op")

KEC, SBOX, SBOXP, K12, K12P = "Keccak-256", "K12-SBox", "K12-SBox-par", "K12", "K12-par"
TX_PER_BLOCK = 100


def read_text(path):
    raw = open(path, "rb").read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8", errors="replace").lstrip("﻿")


def load(dirname):
    ns, mbs, hns = {}, {}, {}
    for fn in sorted(os.listdir(dirname)):
        if not fn.endswith(".txt"):
            continue
        for line in read_text(os.path.join(dirname, fn)).splitlines():
            m = LINE.match(line.strip().lstrip("﻿"))
            if not m:
                continue
            name, rest = m.group(1), m.group(3)
            ns.setdefault(name, []).append(float(m.group(2)))
            if (x := MBS.search(rest)):
                mbs.setdefault(name, []).append(float(x.group(1)))
            if (x := HASH_NS.search(rest)):
                hns.setdefault(name, []).append(float(x.group(1)))
    med = lambda d: {k: statistics.median(v) for k, v in d.items()}
    cv = {k: (statistics.pstdev(v) / statistics.mean(v) * 100 if len(v) > 1 else 0.0) for k, v in ns.items()}
    reps = {k: len(v) for k, v in ns.items()}
    return med(ns), med(mbs), med(hns), cv, reps


def t(v):
    """Format a duration given in ns."""
    if v is None:
        return "-"
    if v >= 1e6:
        return f"{v / 1e6:.2f} ms"
    if v >= 1e3:
        return f"{v / 1e3:.1f} µs"
    return f"{v:.1f} ns"


def r(a, b):
    return "-" if a is None or b is None or b == 0 else f"{a / b:.2f}"


def num(v, d=0):
    return "-" if v is None else f"{v:,.{d}f}".replace(",", " ")


class Out:
    def __init__(self):
        self.lines = []

    def p(self, s=""):
        print(s)
        self.lines.append(s)

    def table(self, title, head, rows, note=None):
        self.p(f"\n### {title}\n")
        self.p("| " + " | ".join(head) + " |")
        self.p("|" + "|".join("---" for _ in head) + "|")
        for row in rows:
            self.p("| " + " | ".join(row) + " |")
        if note:
            self.p(f"\n{note}")


def main():
    args = [a for a in sys.argv[1:]]
    ghz = None
    if "--ghz" in args:
        i = args.index("--ghz")
        ghz = float(args[i + 1])
        del args[i:i + 2]
    d = args[0] if args else "bench_out"
    ns, mbs, hns, cv, reps = load(d)
    if not ns:
        sys.exit(f"no benchmark lines found in {d}/*.txt")
    g = ns.get
    o = Out()
    nrep = max(reps.values())
    o.p(f"# Số liệu thực nghiệm (trung vị của tối đa {nrep} lần chạy, nguồn: {d})")

    # ---------- permutation ----------
    P = "Permutation/"
    if g(P + "SBox-p-12/go"):
        s = g(P + "SBox-p-12/go")
        rows = [[name, t(g(P + key)), r(g(P + key), s)] for name, key in [
            ("Keccak-f 24 vòng (asm)", "Keccak-f-24/asm"), ("Keccak-f 24 vòng (Go)", "Keccak-f-24/go"),
            ("Keccak-p 12 vòng (asm)", "Keccak-p-12/asm"), ("Keccak-p 12 vòng (Go)", "Keccak-p-12/go"),
            ("SBox-p 12 vòng (Go)", "SBox-p-12/go")]]
        o.table("Chi phí một lần gọi hoán vị", ["Hoán vị", "Thời gian", "Tỉ lệ (/SBox-p-12)"], rows,
                f"Một vòng χ–K12 đắt hơn một vòng χ: {r(s, g(P + 'Keccak-p-12/go'))} lần (cùng Go).")

    # ---------- table 3.4 ----------
    rows = []
    for label, key in [("Giá trị băm giao dịch", "T34TxHash/{}/163B"), ("Địa chỉ tài khoản", "T34Address/{}/64B"),
                       ("Merkle root 1000 giao dịch", "T34MerkleTx/{}/1000"),
                       ("State root 1000 tài khoản", "T34StateRoot/{}/1000"),
                       ("State root 10000 tài khoản", "T34StateRoot/{}/10000"),
                       ("State root 100000 tài khoản", "T34StateRoot/{}/100000")]:
        k, s = g(key.format(KEC)), g(key.format(SBOX))
        if k is None and s is None:
            continue
        rows.append([label, t(k), t(s), r(k, s)])
    if rows:
        o.table("Bảng 3.4. So sánh thời gian băm trong các thao tác giao dịch",
                ["Thao tác", "Keccak-256", "KangarooTwelve cải tiến", "Tỉ lệ"], rows,
                "Tỉ lệ = Keccak-256 / KangarooTwelve cải tiến (> 1: K12 cải tiến nhanh hơn).")

    # ---------- table 3.5 ----------
    rows = []
    for n in (1000, 10000, 50000, 200000):
        k, s = g(f"T35Import/{KEC}/{n}"), g(f"T35Import/{SBOX}/{n}")
        if k is None:
            continue
        kt, st = TX_PER_BLOCK / (k / 1e9), TX_PER_BLOCK / (s / 1e9)
        hk = hns.get(f"T35HashShare/{KEC}/{n}")
        share = f"{hk / k * 100:.0f}%" if hk else "-"
        rows.append([str(n), f"{num(kt)} tx/s", f"{num(st)} tx/s", r(st, kt), share])
    if rows:
        o.table("Bảng 3.5. So sánh năng lực xác thực giao dịch của node (giao dịch/giây)",
                ["Số tài khoản", "Keccak-256", "KangarooTwelve cải tiến", "Tỉ lệ", "Tỉ trọng băm (Keccak)"], rows,
                f"Năng lực = {TX_PER_BLOCK} giao dịch / thời gian xác thực và ghi một khối (kèm 32 phiếu bầu). "
                "Tỉ lệ = K12 cải tiến / Keccak-256.")
        rows = [[str(n), t(g(f"T35Import/{KEC}/{n}")), t(g(f"T35Import/{SBOX}/{n}")),
                 r(g(f"T35Import/{KEC}/{n}"), g(f"T35Import/{SBOX}/{n}"))]
                for n in (1000, 10000, 50000, 200000) if g(f"T35Import/{KEC}/{n}")]
        o.table("(Tham khảo) Thời gian xác thực và ghi khối",
                ["Số tài khoản", "Keccak-256", "KangarooTwelve cải tiến", "Tỉ lệ"], rows)

    # ---------- table 3.6 ----------
    sizes = ["64KiB", "256KiB", "1MiB", "4MiB", "16MiB", "64MiB", "256MiB"]
    rows = []
    for sz in sizes:
        k = g(f"T36Large/{KEC}/{sz}")
        if k is None:
            continue
        s1, sp, kp = g(f"T36Large/{SBOX}/{sz}"), g(f"T36Large/{SBOXP}/{sz}"), g(f"T36Large/{K12P}/{sz}")
        rows.append([sz.replace("KiB", " KiB").replace("MiB", " MiB"), t(k), t(s1), t(sp), r(k, s1), r(k, sp), r(k, kp)])
    if rows:
        o.table("Bảng 3.6. So sánh thời gian băm dữ liệu kích thước lớn",
                ["Kích thước", "Keccak-256", "K12 cải tiến (1 luồng)", "K12 cải tiến (song song)",
                 "Tỉ lệ 1 luồng", "Tỉ lệ song song", "K12 gốc song song (tham khảo)"], rows,
                "Tỉ lệ = Keccak-256 / phương án tương ứng. Song song = chế độ cây trên mọi luồng CPU.")
    w1 = g("T36Scaling/K12-SBox-w01/64MiB")
    if w1:
        kref = g(f"T36Large/{KEC}/64MiB")
        rows = []
        for w in (1, 2, 4, 8, 16):
            v = g(f"T36Scaling/K12-SBox-w{w:02d}/64MiB")
            if v:
                rows.append([str(w), t(v), r(w1, v), r(kref, v)])
        o.table("Khả năng mở rộng theo số luồng (64 MiB)",
                ["Số luồng", "Thời gian", "Tăng tốc so với 1 luồng", "So với Keccak-256"], rows)

    # ---------- table 3.7 (proposed use cases) ----------
    rows = []
    for label, key in [("Thân khối 100 giao dịch", "T38BlockBody/{}/100tx"),
                       ("Thân khối 500 giao dịch", "T38BlockBody/{}/500tx"),
                       ("Thân khối 1500 giao dịch", "T38BlockBody/{}/1500tx"),
                       ("Snapshot 10000 tài khoản", "T37Snapshot/{}/10000acc"),
                       ("Snapshot 50000 tài khoản", "T37Snapshot/{}/50000acc"),
                       ("Snapshot 200000 tài khoản", "T37Snapshot/{}/200000acc")]:
        k = g(key.format(KEC))
        if k is None:
            continue
        s1, sp = g(key.format(SBOX)), g(key.format(SBOXP))
        mb = mbs.get(key.format(KEC))
        size = f"{mb * k / 1e3 / 1e3:.0f} KB" if mb else "-"
        rows.append([label, size, t(k), t(s1), t(sp), r(k, s1), r(k, sp)])
    if rows:
        o.table("Bảng 3.7. Kịch bản ứng dụng đề xuất: băm một thông điệp lớn",
                ["Kịch bản", "Kích thước", "Keccak-256", "K12 cải tiến (1 luồng)", "K12 cải tiến (song song)",
                 "Tỉ lệ 1 luồng", "Tỉ lệ song song"], rows,
                "Kịch bản đề xuất: Ethereum hiện không băm thân khối/snapshot như một thông điệp duy nhất.")

    # ---------- hash throughput ----------
    head = ["Phép đo", "Keccak-256", "K12 cải tiến (1 luồng)", "K12 cải tiến (song song)", "Tỉ lệ 1 luồng", "Tỉ lệ song song"]
    rows = []
    for label, key in [("Băm giao dịch 163 B", "T34TxHash/{}/163B"), ("Địa chỉ 64 B", "T34Address/{}/64B")]:
        k, s = g(key.format(KEC)), g(key.format(SBOX))
        if k:
            rows.append([label + " (triệu lần/s)", f"{1e3 / k:.2f}", f"{1e3 / s:.2f}", "-", r(k, s), "-"])
    for sz in ("64KiB", "1MiB", "256MiB"):
        k = mbs.get(f"T36Large/{KEC}/{sz}")
        if k:
            s1, sp = mbs.get(f"T36Large/{SBOX}/{sz}"), mbs.get(f"T36Large/{SBOXP}/{sz}")
            rows.append([f"Dữ liệu {sz} (GB/s)", f"{k / 1e3:.2f}", f"{s1 / 1e3:.2f}", f"{sp / 1e3:.2f}",
                         r(s1, k), r(sp, k)])
    if rows:
        o.table("Thông lượng băm", head, rows, "Tỉ lệ = K12 cải tiến / Keccak-256 (> 1: K12 cải tiến nhanh hơn).")
    if ghz:
        rows = []
        for label, key, nbytes in [("Giao dịch 163 B", "T34TxHash/{}/163B", 163), ("Địa chỉ 64 B", "T34Address/{}/64B", 64),
                                   ("256 MiB", "T36Large/{}/256MiB", 256 << 20)]:
            k, s = g(key.format(KEC)), g(key.format(SBOX))
            if k:
                rows.append([label, f"{k / nbytes * ghz:.1f}", f"{s / nbytes * ghz:.1f}"])
        o.table(f"Số chu kỳ trên byte (quy đổi với f = {ghz} GHz)",
                ["Dữ liệu", "Keccak-256 (c/b)", "K12 cải tiến 1 luồng (c/b)"], rows,
                "c/b = (ns/op / số byte) × f; quy đổi từ thời gian, không đo trực tiếp bằng bộ đếm chu kỳ.")

    # ---------- quality check ----------
    noisy = sorted((k, v) for k, v in cv.items() if v > 5)
    o.p("\n### Kiểm tra độ ổn định\n")
    o.p(f"Số phép đo: {len(ns)}; số lần lặp mỗi phép đo: {min(reps.values())}–{nrep}.")
    if noisy:
        o.p("Các phép đo dao động > 5% (trung vị vẫn dùng được, nhưng nên xem lại log hoặc chạy lại):")
        for k, v in noisy:
            o.p(f"- {k}: {v:.1f}%")
    else:
        o.p("Mọi phép đo dao động ≤ 5%.")

    path = os.path.join(d, "thesis_tables.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(o.lines) + "\n")
    print(f"\n-> đã ghi {path}")


if __name__ == "__main__":
    main()
