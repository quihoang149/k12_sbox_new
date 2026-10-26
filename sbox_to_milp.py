# sbox_to_milp.py — sinh S-box (chi' hoac chi goc) + DDT + rang buoc MILP -> JSON
# Chay trong venv:  python sbox_to_milp.py
import json, io, re
from contextlib import redirect_stdout
from sage.crypto.sbox import SBox
from sboxanalyzer import SboxAnalyzer
 
# ==================== CHON S-BOX ====================
WHICH = "orig"      # "prime" = chi' de xuat  |  "orig" = chi goc (Keccak chuan)
# ===================================================
N = 5                # chi tac dong tren hang 5 bit
 
# chi' de xuat (bac 3) — SUA CHO KHOP CONG THUC CUA BAN neu can:
def chi_prime_bit(x, i):
    m = lambda k: x[(i + k) % 5]
    return (1 ^ m(0) ^ m(1) ^ (m(0)&m(1)) ^ (m(0)&m(2)) ^ (m(2)&m(4))
            ^ (m(0)&m(2)&m(4)) ^ (m(0)&m(3)&m(4))) & 1
 
# chi goc (Keccak chuan, bac 2): y_i = x_i ^ ((x_{i+1}^1)&x_{i+2})
def chi_original_bit(x, i):
    m = lambda k: x[(i + k) % 5]
    return (m(0) ^ ((m(1) ^ 1) & m(2))) & 1
 
BITFUN, OUTFILE = (chi_prime_bit, "chi_prime_diff.json") if WHICH == "prime" \
                  else (chi_original_bit, "chi_orig_diff.json")
 
# bang tra (LUT); quy uoc bit vi tri 0 la MSB (khop a0 cua cong cu)
def build_lut(bitfun):
    lut = []
    for X in range(1 << N):
        x = [(X >> (N - 1 - j)) & 1 for j in range(N)]
        y = [bitfun(x, i) for i in range(N)]
        Y = 0
        for j in range(N):
            Y = (Y << 1) | y[j]
        lut.append(Y)
    return lut
 
lut = build_lut(BITFUN)
sb  = SBox(lut)
print("WHICH =", WHICH, "| LUT =", lut)
 
is_bijective = (sorted(lut) == list(range(1 << N)))
print("Song anh (bijective)?", is_bijective)
try:
    print("Bac dai so:", sb.max_degree())
except Exception as e:
    print("(bo qua:", e, ")")
 
# sinh rang buoc MILP cho DDT (kem bien trong so p0,p1,...)
sa = SboxAnalyzer(sb)
buf = io.StringIO()
with redirect_stdout(buf):
    cnf, milp, cp = sa.minimized_diff_constraints()
log = buf.getvalue()
print(log)
 
weight_terms = []
mline = re.search(r"Weight:\s*(.+)", log)
if mline:
    for coeff, pvar in re.findall(r"([0-9.]+)\s*(p\d+)", mline.group(1)):
        weight_terms.append([float(coeff), pvar])
print("weight_terms =", weight_terms)
 
json.dump({"n": N, "milp": list(milp), "weight_terms": weight_terms,
           "bijective": is_bijective, "lut": lut}, open(OUTFILE, "w"), indent=2)
print(">> Da ghi", OUTFILE, "(", len(milp), "rang buoc )")

