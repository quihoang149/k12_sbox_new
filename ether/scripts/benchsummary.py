#!/usr/bin/env python3
"""Summarise `go test -bench` output into a comparison table and a CSV.

Usage:
    go test ./chain -run '^$' -bench . -benchmem -count 5 > bench_results.txt
    python3 scripts/benchsummary.py bench_results.txt bench_summary.csv [baseline]

Benchmarks are named Group/<Hasher>[/input]. For every group and input the
median ns/op of each hasher is shown, plus speed-ups. The baseline defaults
to Keccak-256; when K12-SBox is present, the table also shows the fair
pure-Go comparison K12-SBox vs Keccak-256-Go and the cost of the new S-box
(K12-SBox vs K12-Go).
"""
import collections
import csv
import re
import statistics
import sys

LINE = re.compile(r"(Benchmark\S+?)-\d+\s+\d+\s+([\d.]+) ns/op")
HASH_NS = re.compile(r"([\d.]+) hash-ns/op")
HASHES = re.compile(r"([\d.]+) hashes/op")
ORDER = ["Keccak-256", "Keccak-256-Go", "K12", "K12-Go", "K12-par", "K12-SBox", "K12-SBox-par"]


def read_text(path):
    """go test output saved by PowerShell 5 (Tee-Object / Out-File) is UTF-16."""
    raw = open(path, "rb").read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8", errors="replace")


def fmt_ns(v):
    if v is None:
        return "-"
    if v >= 1e6:
        return f"{v / 1e6:.2f}ms"
    if v >= 1e3:
        return f"{v / 1e3:.2f}us"
    return f"{v:.0f}ns"


def main(src, dst=None, baseline="Keccak-256"):
    samples = collections.defaultdict(list)
    calls = collections.defaultdict(set)
    for line in read_text(src).splitlines():
        line = line.lstrip("\ufeff")
        m = LINE.match(line)
        if not m:
            continue
        value = float(m.group(2))
        hm = HASH_NS.search(line)
        if hm:  # *HashShare benchmarks: report time inside the hash function
            value = float(hm.group(1))
        samples[m.group(1)].append(value)
        cm = HASHES.search(line)
        if cm:
            group, _, *rest = m.group(1).split("/")
            calls[(group, "/".join(rest))].add(round(float(cm.group(1))))
    for key, vals in calls.items():
        if len(vals) > 1:
            print(f"WARNING {key}: hashes/op differ between hash functions: {sorted(vals)}")

    rows = collections.OrderedDict()
    hashers = set()
    for name, vals in samples.items():
        group, hasher, *rest = name.split("/")
        hashers.add(hasher)
        key = (group.replace("Benchmark", ""), "/".join(rest))
        rows.setdefault(key, {})[hasher] = (statistics.median(vals), statistics.pstdev(vals))

    cols = [h for h in ORDER if h in hashers] + sorted(hashers - set(ORDER))
    ratios = [(h, baseline) for h in cols if h != baseline]
    if "K12-SBox" in hashers:
        for pair in (("K12-SBox", "Keccak-256-Go"), ("K12-SBox", "K12-Go"),
                     ("K12-SBox-par", "Keccak-256-Go"), ("K12-SBox-par", "K12-SBox")):
            if pair[1] in hashers and pair not in ratios:
                ratios.append(pair)

    print("Median time per op; speed-up columns are  (other ÷ hasher) = how many times faster the hasher is.\n")
    print(f"{'benchmark':28}" + "".join(f"{c:>15}" for c in cols) +
          "".join(f"  {a} vs {b}" for a, b in ratios))
    out = []
    for (group, size), v in rows.items():
        label = f"{group}/{size}".rstrip("/")
        line = f"{label:28}" + "".join(f"{fmt_ns(v[c][0] if c in v else None):>15}" for c in cols)
        rec = {"benchmark": group, "input": size}
        for c in cols:
            if c in v:
                rec[f"{c}_ns_median"] = round(v[c][0], 1)
                rec[f"{c}_ns_stdev"] = round(v[c][1], 1)
        for a, b in ratios:
            if a in v and b in v:
                r = v[b][0] / v[a][0]
                rec[f"speedup_{a}_vs_{b}"] = round(r, 3)
                line += f"  {r:>{len(a) + len(b) + 3}.2f}x"
            else:
                line += f"  {'-':>{len(a) + len(b) + 4}}"
        print(line)
        out.append(rec)

    if dst:
        fields = ["benchmark", "input"]
        for c in cols:
            fields += [f"{c}_ns_median", f"{c}_ns_stdev"]
        fields += [f"speedup_{a}_vs_{b}" for a, b in ratios]
        with open(dst, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(out)
        print(f"\nwrote {dst}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(*sys.argv[1:4])
