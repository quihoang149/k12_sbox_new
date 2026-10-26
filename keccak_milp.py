# keccak_milp.py — tìm vệt vi sai Keccak (χ hoặc χ′) bằng MILP + HiGHS
# Chạy trong venv:  python keccak_milp.py
import json, re
import pulp
 
# ==================== THAM SỐ (chỉ chỉnh khối này) ====================
SBOX_FILE = "chi_prime_diff.json"  # file DDT của S-box; đổi sang "chi_orig_diff.json" để đối chứng χ gốc
W          = 4        # độ dài lane. w=1→Keccak-f[25] (ρ biến mất, chỉ để debug); w=4/8 nhỏ; w=64 đầy đủ
ROUNDS     = 2        # số vòng rút gọn. Bắt đầu 2 rồi tăng dần.
OBJECTIVE  = "active" # "active" = đếm S-box hoạt động (DỄ, chạy trước) | "weight" = tổng trọng số (KHÓ)
SOLVER     = "HIGHS"  # "HIGHS" | "SCIP" | "CBC"
TIME_LIMIT = 300      # giây; solver luôn dừng khi chạm mốc này
 
PROVE_LEQ  = None     # None = tìm min bình thường.
                      # Đặt số nguyên K (vd 3) để hỏi "có tồn tại vệt với tiêu chí <= K không?"
                      #   -> Infeasible nghĩa là min > K (dùng để CHỨNG MINH cận dưới)
# ====================================================================
 
# Bảng offset ρ theo FIPS 202, chỉ số [x][y]
RHO = {
    (0,0):0,(0,1):36,(0,2):3, (0,3):41,(0,4):18,
    (1,0):1,(1,1):44,(1,2):10,(1,3):45,(1,4):2,
    (2,0):62,(2,1):6,(2,2):43,(2,3):15,(2,4):61,
    (3,0):28,(3,1):55,(3,2):25,(3,3):21,(3,4):56,
    (4,0):27,(4,1):20,(4,2):39,(4,3):8, (4,4):14,
}
 
with open(SBOX_FILE) as f:
    S = json.load(f)
SBOX_MILP    = S["milp"]
WEIGHT_TERMS = S["weight_terms"]            # vd [[4.0,'p0'],[3.0,'p1']]
WEIGHT_MIN   = min(t[0] for t in WEIGHT_TERMS)   # trọng số nhỏ nhất của 1 S-box hoạt động
 
prob = pulp.LpProblem("keccak_diff_trail", pulp.LpMinimize)
_uid = [0]
def newvar(prefix, cat="Binary", up=None):
    _uid[0] += 1
    return pulp.LpVariable(f"{prefix}_{_uid[0]}", lowBound=0, upBound=up, cat=cat)
 
def xor_eq(inputs, out):
    """Rang buoc parity: out = XOR(inputs).  Sum inputs - out = 2*d."""
    k = len(inputs)
    d = newvar("d", cat="Integer", up=k // 2)
    prob.addConstraint(pulp.lpSum(inputs) - out - 2 * d == 0)
 
def new_state(tag):
    return {(x, y, z): newvar(f"{tag}_{x}{y}{z}")
            for x in range(5) for y in range(5) for z in range(W)}
 
def apply_theta(A):
    C = {}
    for x in range(5):
        for z in range(W):
            c = newvar("C"); xor_eq([A[(x, y, z)] for y in range(5)], c); C[(x, z)] = c
    D = {}
    for x in range(5):
        for z in range(W):
            dd = newvar("D"); xor_eq([C[((x - 1) % 5, z)], C[((x + 1) % 5, (z - 1) % W)]], dd); D[(x, z)] = dd
    AT = new_state("AT")
    for x in range(5):
        for y in range(5):
            for z in range(W):
                xor_eq([A[(x, y, z)], D[(x, z)]], AT[(x, y, z)])
    return AT
 
def apply_rho(A):     # doi nhan: A'[x,y,z] = A[x,y,(z-off) mod W]
    return {(x, y, z): A[(x, y, (z - RHO[(x, y)]) % W)]
            for x in range(5) for y in range(5) for z in range(W)}
 
def apply_pi(A):      # doi nhan: A'[x,y,z] = A[(x+3y) mod5, x, z]
    return {(x, y, z): A[((x + 3 * y) % 5, x, z)]
            for x in range(5) for y in range(5) for z in range(W)}
 
def add_sbox(inb, outb):
    """Ap rang buoc DDT cho 1 hang 5 bit; tra ve bieu thuc trong so cua S-box do."""
    npv = 1 + max([int(re.findall(r'p(\d+)', c)[-1]) for c in SBOX_MILP if 'p' in c] + [-1])
    P = [newvar("p") for _ in range(npv)]
    env = {f"a{j}": inb[j] for j in range(5)}
    env.update({f"b{j}": outb[j] for j in range(5)})
    env.update({f"p{j}": P[j] for j in range(npv)})
    for con in SBOX_MILP:
        lhs_str, rhs = con.split(">=")
        rhs = int(rhs)
        expr, sign = [], 1
        for t in lhs_str.split():
            if t == '+': sign = 1
            elif t == '-': sign = -1
            else:
                expr.append(sign * env[t]); sign = 1
        prob.addConstraint(pulp.lpSum(expr) >= rhs)
    return pulp.lpSum(WEIGHT_TERMS[k][0] * P[k] for k in range(len(WEIGHT_TERMS)))
 
def apply_chi(A):
    AC = new_state("AC")
    wexpr, act_exprs = [], []
    for y in range(5):
        for z in range(W):
            inb  = [A[(x, y, z)]  for x in range(5)]
            outb = [AC[(x, y, z)] for x in range(5)]
            wexpr.append(add_sbox(inb, outb))
            act = newvar("act")                       # =1 neu hang co hieu vao khac 0
            prob.addConstraint(act <= pulp.lpSum(inb))
            for a in inb:
                prob.addConstraint(act >= a)
            act_exprs.append(act)
    return AC, pulp.lpSum(wexpr), pulp.lpSum(act_exprs)
 
# ---------------- Dung nhieu vong ----------------
state = new_state("IN")
prob += (pulp.lpSum(state.values()) >= 1)   # hieu dau vao != 0
total_weight, total_active = [], []
for r in range(ROUNDS):
    state = apply_theta(state)
    state = apply_rho(state)
    state = apply_pi(state)
    state, w, a = apply_chi(state)
    total_weight.append(w)
    total_active.append(a)
 
metric = pulp.lpSum(total_active) if OBJECTIVE == "active" else pulp.lpSum(total_weight)
 
# ---------------- Ham muc tieu / che do chung minh ----------------
if PROVE_LEQ is None:
    prob += metric                              # tim min binh thuong
else:
    prob += 0                                   # bai toan quyet dinh
    prob += (metric <= PROVE_LEQ)               # "ton tai ve voi metric <= K ?"
 
# ---------------- Banner ----------------
print("=" * 60)
print(f"  SBOX={SBOX_FILE}  W={W}  ROUNDS={ROUNDS}")
print(f"  OBJECTIVE={OBJECTIVE}  SOLVER={SOLVER}  PROVE_LEQ={PROVE_LEQ}")
print(f"  weight_min(S-box) = {WEIGHT_MIN:.0f}")
print(f"  So rang buoc: {len(prob.constraints)}  |  So bien: {len(prob.variables())}")
print("=" * 60)
 
# ---------------- Giai ----------------
if SOLVER == "HIGHS":
    solver = pulp.HiGHS(msg=True, timeLimit=TIME_LIMIT, gapRel=0.0, threads=4)
elif SOLVER == "SCIP":
    solver = pulp.SCIP_PY(msg=True, timeLimit=TIME_LIMIT)
else:
    solver = pulp.PULP_CBC_CMD(msg=True, threads=4, timeLimit=TIME_LIMIT)
prob.solve(solver)
 
# ---------------- Ket qua ----------------
status = pulp.LpStatus[prob.status]
print("\n" + "-" * 60)
print("Trang thai :", status)
 
if PROVE_LEQ is not None:
    if status == "Infeasible":
        print(f"KET LUAN: KHONG ton tai ve voi {OBJECTIVE} <= {PROVE_LEQ}")
        print(f"      ==> gia tri nho nhat > {PROVE_LEQ} (da CHUNG MINH).")
    elif status in ("Optimal", "Feasible"):
        print(f"KET LUAN: TON TAI ve voi {OBJECTIVE} <= {PROVE_LEQ}.")
        print(f"      ==> hay ha PROVE_LEQ xuong nua de tim day that.")
    else:
        print("Khong ket luan duoc (het gio truoc khi xong). Tang TIME_LIMIT.")
else:
    best = pulp.value(prob.objective)
    if OBJECTIVE == "active":
        print(f"So S-box hoat dong (nghiem tot nhat tim duoc): {best:.0f}")
        print(f"Can tren trong so ve: {best:.0f} x weight_min({WEIGHT_MIN:.0f}) = {best*WEIGHT_MIN:.0f}")
        print(f"=> P(ve tot nhat) <= 2^(-{best*WEIGHT_MIN:.0f})")
    else:
        print(f"Trong so vi sai (nghiem tot nhat tim duoc): {best:.3f}")
        print(f"=> P(ve tot nhat) ~ 2^(-{best:.3f})")
    print("LUU Y: neu HiGHS bao 'Time limit reached / gap>0' thi day moi la CAN TREN,")
    print("       chua phai min da chung minh. Dung PROVE_LEQ de chung minh can duoi.")
print("-" * 60)

