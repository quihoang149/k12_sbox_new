#!/usr/bin/env python3
"""
Exact minimum-weight differential (DC) / linear (LC) trail search for
Keccak-f[b] with an arbitrary 5-bit row S-box, using a SAT solver.

Model of an R-round trail (R >= 2), same convention as KeccakTools
("trail core" + first/last rounds minimised):
    round 0      : only the S-box OUTPUT pattern b0 is a variable; its cost is
                   the minimum reverse weight  w_rev(b0) = min_a w(a -> b0)
    rounds 1..R-2: input a_r and output b_r with the exact DDT/LAT weight
    round R-1    : only the S-box INPUT pattern a_{R-1}; cost = min_b w(a -> b)
    linear layer : DC  a_{r+1} = pi(rho(theta(b_r)))
                   LC  b_r     = lambda^T(a_{r+1})   (masks)
The minimum of this objective equals the minimum weight over all R-round
trails (the first input and the last output are free).

For each weight bound T the solver decides whether a trail with weight <= T
exists; T is increased from a lower bound until SAT. Each UNSAT answer is a
proof that no trail of weight <= T exists, so the first SAT value is the
exact minimum. Every trail found is re-verified independently with
keccak_model.py (which matches KeccakTools bit for bit).

Usage:
  python3 sat_trailsearch.py --width 1600 --rounds 3 --mode DC [--sbox new|chi]
"""
import argparse, math, sys, time, random, json, os
from pysat.formula import IDPool
from pysat.solvers import Solver
from keccak_model import KeccakModel, CHI, NEW, RHO


# ---------------------------------------------------------------- S-box tables
def ddt_table(S):
    cnt = {}
    for a in range(32):
        for x in range(32):
            b = S[x] ^ S[x ^ a]
            cnt[(a, b)] = cnt.get((a, b), 0) + 1
    return {k: int(round(5 - math.log2(c))) for k, c in cnt.items()}


def lat_table(S):
    """(u_in, v_out) -> -log2(c^2) for nonzero correlations"""
    res = {}
    for u in range(32):
        for v in range(32):
            c = sum((-1) ** ((bin(u & x).count('1') + bin(v & S[x]).count('1')) & 1) for x in range(32))
            if c:
                res[(u, v)] = int(round(2 * (5 - math.log2(abs(c)))))
    return res


# ---------------------------------------------------------------- CNF of a small relation
def prime_cover(F, n):
    """CNF clauses (as cubes) excluding the set F of n-bit points.
    Quine-McCluskey primes of F + greedy set cover."""
    level = {(v, 0) for v in F}
    primes = set()
    while level:
        nxt = set(); merged = set()
        for (v, m) in level:
            for i in range(n):
                bit = 1 << i
                if m & bit or v & bit:
                    continue
                p = (v | bit, m)
                if p in level:
                    nxt.add((v, m | bit)); merged.add((v, m)); merged.add(p)
        primes |= (level - merged)
        level = nxt
    # greedy cover
    def pts(c):
        v, m = c
        free = [i for i in range(n) if m >> i & 1]
        out = []
        for k in range(1 << len(free)):
            x = v
            for j, i in enumerate(free):
                if k >> j & 1:
                    x |= 1 << i
            out.append(x)
        return out
    cov = {c: set(pts(c)) for c in primes}
    todo = set(F); chosen = []
    while todo:
        best = max(cov, key=lambda c: len(cov[c] & todo))
        chosen.append(best); todo -= cov[best]
    return chosen


def relation_cnf(allowed_fn, nbits, cache_key):
    """allowed_fn(point)->bool over nbits; returns list of cubes (v,m) to forbid."""
    cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cnf_cache.json")
    db = {}
    if os.path.exists(cache):
        try:
            db = json.load(open(cache))
        except Exception:
            db = {}
    if cache_key in db:
        return [tuple(c) for c in db[cache_key]]
    F = [p for p in range(1 << nbits) if not allowed_fn(p)]
    cubes = prime_cover(F, nbits)
    # self-check
    for p in range(1 << nbits):
        hit = any((p & ~m) == v for (v, m) in cubes)
        assert hit == (not allowed_fn(p))
    db[cache_key] = cubes
    json.dump(db, open(cache, "w"))
    return cubes


# ---------------------------------------------------------------- model
class SatTrail:
    def __init__(self, width, rounds, mode, sbox, sboxname):
        assert rounds >= 2
        self.W = width // 25; self.R = rounds; self.mode = mode; self.S = sbox
        self.pool = IDPool(); self.clauses = []; self.xors = []; self.n_xor_clauses = 0; self.xor_clauses_list = []
        W = self.W
        self.perm = {}
        for x in range(5):
            for y in range(5):
                for z in range(W):
                    self.perm[(x, y, z)] = (y, (2 * x + 3 * y) % 5, (z + RHO[x][y]) % W)
        tab = ddt_table(sbox) if mode == "DC" else lat_table(sbox)
        self.tab = tab
        # first-round reverse min weight per output row, last-round min per input row
        self.wrev = [min([w for (a, b), w in tab.items() if b == o and a] or [99]) for o in range(32)]
        self.wfwd = [min([w for (a, b), w in tab.items() if a == i and b] or [99]) for i in range(32)]
        self.wrev[0] = self.wfwd[0] = 0
        allw = [w for (a, b), w in tab.items() if a]
        self.wmin = min(allw); wmax = max(allw)
        self.k = wmax - self.wmin          # number of unary "extra weight" bits per row
        self.key = f"{sboxname}-{mode}"
        self.matsui = False
        self.kernel_case = ""
        self.theta_e = False
        self.lb = {1: self.wmin}

    def v(self, name):
        return self.pool.id(name)

    def xor_eq(self, out, ins):
        """out = XOR(ins) as CNF (ins small)."""
        self.xors.append(list(ins) + [out])
        lits = list(ins) + [out]
        n = len(lits)
        for k in range(1 << n):
            # forbid assignments with odd parity of (ins..., out) -> need XOR(ins)^out == 0
            if bin(k).count('1') % 2 == 1:
                self.n_xor_clauses += 1
                self.xor_clauses_list.append([(-l if (k >> i) & 1 else l) for i, l in enumerate(lits)])

    def state(self, name):
        return {p: self.v(f"{name}_{p}") for p in self.perm}

    def add_rows(self, tag, inb, outb, kind):
        """kind: 'first' (outb only), 'mid' (inb,outb), 'last' (inb only).
        Returns list of weight literals (with multiplicity) for this layer."""
        W = self.W; k = self.k; wmin = self.wmin
        if kind == "mid":
            def allowed(p):
                a = p & 31; b = (p >> 5) & 31; e = (p >> 10)
                if (a, b) not in self.tab:
                    return False
                w = self.tab[(a, b)] if a else 0
                need = w - wmin if a else 0
                ebits = [(e >> j) & 1 for j in range(k)]
                if any(ebits[j + 1] > ebits[j] for j in range(k - 1)):
                    return False
                return sum(ebits) >= need and (a or sum(ebits) == 0)
            nb = 10 + k
        else:
            table = self.wrev if kind == "first" else self.wfwd
            def allowed(p):
                r = p & 31; e = p >> 5
                ebits = [(e >> j) & 1 for j in range(k)]
                if any(ebits[j + 1] > ebits[j] for j in range(k - 1)):
                    return False
                need = table[r] - wmin if r else 0
                return table[r] < 99 and sum(ebits) >= need and (r or sum(ebits) == 0)
            nb = 5 + k
        cubes = relation_cnf(allowed, nb, f"{self.key}-{kind}-k{k}-wmin{wmin}")
        wl = []
        for y in range(5):
            for z in range(W):
                if kind == "mid":
                    bits = [inb[(x, y, z)] for x in range(5)] + [outb[(x, y, z)] for x in range(5)]
                    actsrc = [inb[(x, y, z)] for x in range(5)]
                elif kind == "first":
                    bits = [outb[(x, y, z)] for x in range(5)]; actsrc = bits
                else:
                    bits = [inb[(x, y, z)] for x in range(5)]; actsrc = bits
                ex = [self.v(f"e_{tag}_{y}_{z}_{j}") for j in range(k)]
                allbits = bits + ex
                for (val, m) in cubes:
                    cl = []
                    for i in range(nb):
                        if m >> i & 1:
                            continue
                        cl.append(-allbits[i] if (val >> i) & 1 else allbits[i])
                    self.clauses.append(cl)
                # activity: each active row costs wmin
                act = self.v(f"act_{tag}_{y}_{z}")
                for b in actsrc:
                    self.clauses.append([-b, act])
                wl += [(act, wmin)] + [(e, 1) for e in ex]
        return wl

    def build(self):
        W, R = self.W, self.R
        # states: b[0], (a[r], b[r]) r=1..R-2, a[R-1]
        a = {r: self.state(f"a{r}") for r in range(1, R)}
        b = {r: self.state(f"b{r}") for r in range(0, R - 1)}
        self.a, self.b = a, b
        self.Cvars = {}
        for r in range(R - 1):
            C = {(x, z): self.v(f"C{r}_{x}_{z}") for x in range(5) for z in range(W)}
            self.Cvars[r] = list(C.values())
            if self.mode == "DC":
                src = b[r]
                for x in range(5):
                    for z in range(W):
                        self.xor_eq(C[(x, z)], [src[(x, y, z)] for y in range(5)])
                if self.theta_e:
                    E = {(x, z): self.v(f"E{r}_{x}_{z}") for x in range(5) for z in range(W)}
                    for x in range(5):
                        for z in range(W):
                            self.xor_eq(E[(x, z)], [C[((x - 1) % 5, z)], C[((x + 1) % 5, (z - 1) % W)]])
                    for (x, y, z) in self.perm:
                        self.xor_eq(a[r + 1][self.perm[(x, y, z)]], [src[(x, y, z)], E[(x, z)]])
                else:
                    for (x, y, z) in self.perm:
                        self.xor_eq(a[r + 1][self.perm[(x, y, z)]],
                                    [src[(x, y, z)], C[((x - 1) % 5, z)], C[((x + 1) % 5, (z - 1) % W)]])
            else:
                w = {p: a[r + 1][self.perm[p]] for p in self.perm}
                for x in range(5):
                    for z in range(W):
                        self.xor_eq(C[(x, z)], [w[(x, y, z)] for y in range(5)])
                if self.theta_e:
                    E = {(x, z): self.v(f"E{r}_{x}_{z}") for x in range(5) for z in range(W)}
                    for x in range(5):
                        for z in range(W):
                            self.xor_eq(E[(x, z)], [C[((x + 1) % 5, z)], C[((x - 1) % 5, (z + 1) % W)]])
                    for (x, y, z) in self.perm:
                        self.xor_eq(b[r][(x, y, z)], [w[(x, y, z)], E[(x, z)]])
                else:
                    for (x, y, z) in self.perm:
                        self.xor_eq(b[r][(x, y, z)],
                                    [w[(x, y, z)], C[((x + 1) % 5, z)], C[((x - 1) % 5, (z + 1) % W)]])
        wl = self.add_rows("r0", None, b[0], "first")
        self.round_sizes = [len(wl)]
        for r in range(1, R - 1):
            t = self.add_rows(f"r{r}", a[r], b[r], "mid"); wl += t; self.round_sizes.append(len(t))
        t = self.add_rows(f"r{R-1}", a[R - 1], None, "last"); wl += t; self.round_sizes.append(len(t))
        self.wlits = wl
        # optional case split on the column parities (CP-kernel) of each linear layer
        for r, c in enumerate(self.kernel_case):
            if c == "K":
                self.clauses += [[-v] for v in self.Cvars[r]]
            elif c == "N":
                self.clauses.append(list(self.Cvars[r]))
        # nontrivial + translation symmetry: an active slice of b0 at z = 0
        self.clauses.append([b[0][(x, y, 0)] for x in range(5) for y in range(5)])

    def _counter(self, lits, K, tag):
        """Weighted sequential counter over lits=[(x,w)]; returns list of
        register dicts after each position: reg[i][j] is forced true when the
        weight of lits[0..i] is >= j."""
        prev = {}; regs = []
        for i, (x, w) in enumerate(lits):
            cur = {j: self.v(f"sc{tag}_{i}_{j}") for j in range(1, K + 1)}
            for j in range(1, K + 1):
                if j in prev:
                    self.clauses.append([-prev[j], cur[j]])
                if j <= w:
                    self.clauses.append([-x, cur[j]])
                elif (j - w) in prev:
                    self.clauses.append([-x, -prev[j - w], cur[j]])
            prev = cur; regs.append(cur)
        return regs

    def add_counter(self, K):
        """Forward counter (total weight) + Matsui-like bounding conditions on
        round prefixes/suffixes (forward and backward counters)."""
        regs = self._counter(self.wlits, K, "f")
        self.top_counter = regs[-1]
        self.prefix_regs = {}
        self.suffix_regs = {}
        if self.matsui:
            # end index of every round in wlits
            ends = []; acc = 0
            for n in self.round_sizes:
                acc += n; ends.append(acc - 1)
            for k in range(len(ends) - 1):          # prefix rounds 0..k
                self.prefix_regs[k] = regs[ends[k]]
            rev = list(reversed(self.wlits))
            rregs = self._counter(rev, K, "b")
            acc = 0
            for k in range(len(self.round_sizes) - 1, 0, -1):   # suffix rounds k..R-1
                acc += self.round_sizes[k]
                self.suffix_regs[k] = rregs[acc - 1]

    def assumptions(self, T):
        """total <= T and Matsui conditions using lower bounds self.lb[m]
        (min weight of any m consecutive rounds, m>=1)."""
        A = [-self.top_counter[T + 1]]
        R = self.R
        for k, reg in self.prefix_regs.items():      # rounds 0..k, remaining R-1-k rounds
            rem = R - 1 - k
            bound = T - self.lb.get(rem, 0)
            if bound + 1 in reg:
                if bound < 0:
                    return None
                A.append(-reg[bound + 1])
        for k, reg in self.suffix_regs.items():      # rounds k..R-1, first k rounds before
            bound = T - self.lb.get(k, 0)
            if bound + 1 in reg:
                if bound < 0:
                    return None
                A.append(-reg[bound + 1])
        return A

    def solve_incremental(self, Tstart, Tmax, solver="cadical195", log=print):
        self.add_counter(Tmax + 1)
        if solver == "cms":
            import pycryptosat
            s = pycryptosat.Solver(threads=1)
            for c in self.clauses:
                s.add_clause(c)
            for x in self.xors:
                s.add_xor_clause(x, False)
            T = Tstart
            while T <= Tmax:
                t = time.time()
                ok, sol = s.solve(assumptions=self.assumptions(T))
                log(f"#   weight <= {T}: {'SAT' if ok else 'UNSAT'} ({time.time()-t:.1f}s)")
                if ok:
                    return T, [i if sol[i] else -i for i in range(1, len(sol))]
                T += 1
            return None, None
        with Solver(name=solver, bootstrap_with=self.clauses + self.xor_clauses_list) as s:
            T = Tstart
            while T <= Tmax:
                t = time.time()
                ok = s.solve(assumptions=self.assumptions(T))
                log(f"#   weight <= {T}: {'SAT' if ok else 'UNSAT'} ({time.time()-t:.1f}s)")
                if ok:
                    return T, s.get_model()
                T += 1
        return None, None

    def write_dimacs(self, T, path, Tmax=None):
        """CNF with the bound 'weight <= T' as unit clauses (for external solvers)."""
        if not hasattr(self, "top_counter"):
            self.add_counter((Tmax or T) + 1)
        A = self.assumptions(T)
        cls = self.clauses + self.xor_clauses_list + [[l] for l in A]
        with open(path, "w") as f:
            f.write(f"p cnf {self.pool.top} {len(cls)}\n")
            for c in cls:
                f.write(" ".join(map(str, c)) + " 0\n")

    def solve_external(self, Tstart, Tmax, exe, workdir, log=print):
        import subprocess, tempfile
        self.add_counter(Tmax + 1)
        T = Tstart
        while T <= Tmax:
            path = os.path.join(workdir, f"bound_{os.getpid()}_{T}.cnf")
            self.write_dimacs(T, path)
            t = time.time()
            r = subprocess.run([exe, "-q", path], capture_output=True, text=True)
            os.remove(path)
            ok = r.returncode == 10
            if r.returncode not in (10, 20):
                raise RuntimeError("external solver failed: " + r.stdout[-500:] + r.stderr[-500:])
            log(f"#   weight <= {T}: {'SAT' if ok else 'UNSAT'} ({time.time()-t:.1f}s, {os.path.basename(exe)})")
            if ok:
                model = []
                for line in r.stdout.splitlines():
                    if line.startswith("v "):
                        model += [int(x) for x in line[2:].split() if x != "0"]
                return T, model
            T += 1
        return None, None

    def solve_once(self, T, exe=None, workdir="/tmp", solver="cadical195"):
        import subprocess
        if exe:
            path = os.path.join(workdir, f"bound_{os.getpid()}_{T}.cnf")
            self.write_dimacs(T, path)
            r = subprocess.run([exe, "-q", path], capture_output=True, text=True)
            os.remove(path)
            if r.returncode not in (10, 20):
                raise RuntimeError("external solver failed")
            if r.returncode == 20:
                return False, None
            model = []
            for line in r.stdout.splitlines():
                if line.startswith("v "):
                    model += [int(x) for x in line[2:].split() if x != "0"]
            return True, model
        with Solver(name=solver, bootstrap_with=self.clauses + self.xor_clauses_list) as sv:
            ok = sv.solve(assumptions=self.assumptions(T))
            return ok, (sv.get_model() if ok else None)

    def solve_down(self, Tstart, known_lb, exe, workdir, solver, S, log=print):
        """Descending search: SAT at T gives a trail of weight w <= T, then try
        w-1, ... until UNSAT (proof) or below a proven lower bound."""
        self.add_counter(Tstart + 1)
        T = Tstart; best = None
        while T >= known_lb:
            t = time.time()
            ok, model = self.solve_once(T, exe, workdir, solver)
            log(f"#   weight <= {T}: {'SAT' if ok else 'UNSAT'} ({time.time()-t:.1f}s)")
            if not ok:
                break
            full = self.complete(self.extract(model))
            w, per = verify(full, 25 * self.W, self.mode, S, self.tab)
            log(f"#     found trail of weight {w} {per}")
            best = (w, full); T = w - 1
        return best

    def extract(self, model):
        pos = set(l for l in model if l > 0)
        val = lambda vid: vid in pos
        W, R = self.W, self.R
        trail = []
        for r in range(R):
            rows = []
            for y in range(5):
                for z in range(W):
                    ai = sum(val(self.a[r][(x, y, z)]) << x for x in range(5)) if r in self.a else None
                    bi = sum(val(self.b[r][(x, y, z)]) << x for x in range(5)) if r in self.b else None
                    if ai or bi:
                        rows.append((y, z, ai, bi))
            trail.append(rows)
        return trail

    def complete(self, trail):
        """fill the free first input / last output with optimal choices"""
        full = []
        for r, rows in enumerate(trail):
            nr = []
            for (y, z, ai, bi) in rows:
                if ai is None:
                    ai = min((a for (a, bb), w in self.tab.items() if bb == bi and a), key=lambda a: self.tab[(a, bi)])
                if bi is None:
                    bi = min((bb for (aa, bb), w in self.tab.items() if aa == ai and bb), key=lambda bb: self.tab[(ai, bb)])
                nr.append((y, z, ai, bi))
            full.append(nr)
        return full


def lanes_of(rows, W, idx):
    A = [[0] * 5 for _ in range(5)]
    for row in rows:
        y, z, v = row[0], row[1], row[idx]
        for x in range(5):
            if (v >> x) & 1:
                A[x][y] |= 1 << z
    return A


def verify(full, width, mode, S, tab):
    m = KeccakModel(width, S); W = m.w
    tot = 0; per = []
    for rows in full:
        wr = 0
        for (y, z, a, b) in rows:
            assert (a, b) in tab and a and b
            wr += tab[(a, b)]
        per.append(wr); tot += wr
    for r in range(len(full) - 1):
        bst = lanes_of(full[r], W, 3); ast = lanes_of(full[r + 1], W, 2)
        if mode == "DC":
            assert m.pi(m.rho(m.theta(bst))) == ast, "linear layer mismatch"
        else:
            for _ in range(64):
                X = [[random.getrandbits(W) for _ in range(5)] for _ in range(5)]
                LX = m.pi(m.rho(m.theta(X)))
                l = sum(bin(LX[i][j] & ast[i][j]).count('1') for i in range(5) for j in range(5)) & 1
                rr = sum(bin(X[i][j] & bst[i][j]).count('1') for i in range(5) for j in range(5)) & 1
                assert l == rr, "transpose mismatch"
    return tot, per


def fmt(full, mode):
    nm = ("diff", "diff") if mode == "DC" else ("mask", "mask")
    out = []
    for r, rows in enumerate(full):
        out.append(f"  round {r}: {len(rows)} active rows")
        for (y, z, a, b) in rows:
            out.append(f"    (y={y}, z={z:2d}): in {nm[0]} 0x{a:02x} -> out {nm[1]} 0x{b:02x}")
    return "\n".join(out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--width", type=int, default=1600)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--mode", choices=["DC", "LC"], default="DC")
    ap.add_argument("--sbox", choices=["new", "chi"], default="new")
    ap.add_argument("--start", type=int, default=None, help="first bound T to try")
    ap.add_argument("--solver", default="cadical195")
    ap.add_argument("--tmax", type=int, default=64, help="largest bound tried")
    ap.add_argument("--external", default=None, help="path to an external DIMACS solver (e.g. kissat); one call per bound")
    ap.add_argument("--down", type=int, default=None, help="descending search starting at this bound")
    ap.add_argument("--known-lb", type=int, default=0, help="weight already proven to be a lower bound (stop there)")
    ap.add_argument("--kernel-case", default="", help="per linear layer: K = state before theta in CP-kernel, N = not, ? = free; e.g. KN")
    ap.add_argument("--theta-e", action="store_true", help="encode theta with explicit theta-effect variables E")
    ap.add_argument("--workdir", default="/tmp", help="where temporary CNF files are written")
    ap.add_argument("--lb", type=str, default="", help="known min weights for fewer rounds, e.g. '2:14' (enables Matsui-like bounding)")
    args = ap.parse_args()
    S = NEW if args.sbox == "new" else CHI
    st = SatTrail(args.width, args.rounds, args.mode, S, args.sbox)
    if args.lb:
        st.matsui = True
        for item in args.lb.split(","):
            m_, v_ = item.split(":"); st.lb[int(m_)] = int(v_)
    st.kernel_case = args.kernel_case
    st.theta_e = args.theta_e
    st.build()
    T = args.start if args.start is not None else st.wmin * args.rounds
    print(f"# b={args.width} R={args.rounds} {args.mode} sbox={args.sbox}: "
          f"{st.pool.top} vars, {len(st.clauses)} clauses (before counter)", flush=True)
    t0 = time.time()
    if args.down is not None:
        best = st.solve_down(args.down, args.known_lb, args.external, args.workdir, args.solver, S,
                             log=lambda m: print(m, flush=True))
        if best is None:
            print(f"RESULT b={args.width} rounds={args.rounds} mode={args.mode} sbox={args.sbox} min_weight > {args.down}")
            sys.exit(0)
        w, full = best
        tot, per = verify(full, args.width, args.mode, S, st.tab)
        print(f"RESULT b={args.width} rounds={args.rounds} mode={args.mode} sbox={args.sbox} "
              f"min_weight={tot} per_round={per} total_time={time.time()-t0:.1f}s")
        print(fmt(full, args.mode), flush=True)
        sys.exit(0)
    if args.external:
        T, model = st.solve_external(T, args.tmax, args.external, args.workdir, log=lambda m: print(m, flush=True))
    else:
        T, model = st.solve_incremental(T, args.tmax, args.solver, log=lambda m: print(m, flush=True))
    if T is None:
        print(f"RESULT b={args.width} rounds={args.rounds} mode={args.mode} sbox={args.sbox} "
              f"min_weight > {args.tmax}"); sys.exit(0)
    full = st.complete(st.extract(model))
    tot, per = verify(full, args.width, args.mode, S, st.tab)
    assert tot == T, (tot, T)
    print(f"RESULT b={args.width} rounds={args.rounds} mode={args.mode} sbox={args.sbox} "
          f"min_weight={tot} per_round={per} total_time={time.time()-t0:.1f}s")
    print(fmt(full, args.mode), flush=True)
