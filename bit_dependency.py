import collections
W  = 64
N  = 5 * 5 * W
SBOX_ORIG = [
    0x00,0x09,0x12,0x0b,0x05,0x0c,0x16,0x0f,
    0x0a,0x03,0x18,0x01,0x0d,0x04,0x1e,0x07,
    0x14,0x15,0x06,0x17,0x11,0x10,0x02,0x13,
    0x1a,0x1b,0x08,0x19,0x1d,0x1c,0x0e,0x1f
]
SBOX_K12 = [
    0x1f,0x0e,0x1c,0x0c,0x19,0x01,0x18,0x05,
    0x13,0x08,0x02,0x1a,0x11,0x0b,0x0a,0x17,
    0x07,0x06,0x10,0x12,0x04,0x0d,0x15,0x1b,
    0x03,0x09,0x16,0x1d,0x14,0x1e,0x0f,0x00
]
def bit_idx(x, y, z): return (x*5+y)*W + z
def sbox_dep(sbox):
    dep = [set() for _ in range(5)]
    for ob in range(5):
        for ib in range(5):
            for x in range(32):
                if ((sbox[x]>>ob)&1) != ((sbox[x^(1<<ib)]>>ob)&1):
                    dep[ob].add(ib); break
    return dep
def theta_orig(state):
    C = {}
    for x in range(5):
        for z in range(W):
            d = frozenset()
            for y in range(5): d |= state[(x,y,z)]
            C[(x,z)] = d
    D = {}
    for x in range(5):
        for z in range(W):
            D[(x,z)] = C[(x-1)%5, z] | C[(x+1)%5, (z-1)%W]
    ns = {}
    for x in range(5):
        for y in range(5):
            for z in range(W):
                ns[(x,y,z)] = state[(x,y,z)] | D[(x,z)]
    return ns
def rho_pi(state):
    ro = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],
          [28,55,25,21,56],[27,20,39,8,14]]
    ns = {}
    for x in range(5):
        for y in range(5):
            for z in range(W):
                nx=y; ny=(2*x+3*y)%5; oz=(z-ro[x][y])%W
                ns[(nx,ny,z)] = state[(x,y,oz)]
    return ns
def chi(state, sbox):
    sd = sbox_dep(sbox)
    ns = {}
    for y in range(5):
        for z in range(W):
            row = [state[(x,y,z)] for x in range(5)]
            for ob in range(5):
                d = frozenset()
                for ib in sd[ob]: d |= row[ib]
                ns[(ob,y,z)] = d
    return ns
def analyze(theta_fn, sbox, name):
    print(f"\n{'='*65}")
    print(f"  {name}")
    print(f"{'='*65}")
    state = {(x,y,z): frozenset([bit_idx(x,y,z)])
             for x in range(5) for y in range(5) for z in range(W)}
    state = theta_fn(state)
    sizes_th = [len(state[(x,y,z)])
                for x in range(5) for y in range(5) for z in range(W)]
    print(f"\n  Sau θ : {dict(collections.Counter(sizes_th))}")
    state = rho_pi(state)
    state = chi(state, sbox)
    sizes = [len(state[(x,y,z)])
             for x in range(5) for y in range(5) for z in range(W)]
    cnt = collections.Counter(sizes)
    print(f"  Sau χ : {dict(cnt)}")
    print(f"\n  *** FORMAT ***")
    cumul = 0
    for k in sorted(cnt):
        cumul += cnt[k]
        print(f"  {cnt[k]:>5} bit đầu ra phụ thuộc vào đúng {k:>3} bit đầu vào")
    print(f"  ---")
    cumul = 0
    for k in sorted(cnt):
        cumul += cnt[k]
        print(f"  {cumul:>5} bit đầu ra phụ thuộc vào  ≤  {k:>3} bit đầu vào")
    print(f"\n  min={min(sizes)}  max={max(sizes)}  avg={sum(sizes)/len(sizes):.1f}")
    return cnt
print("="*65)
print("  BIT DEPENDENCY - SO SÁNH chi GỐC vs chi-K12 (đề xuất)")
print("  (chỉ dùng θ gốc — không dùng biến thể STCPM)")
print("="*65)
c1 = analyze(theta_orig, SBOX_ORIG, "① Keccak gốc      (θ_gốc + χ_gốc, bậc 2)")
c2 = analyze(theta_orig, SBOX_K12,  "② Đề xuất          (θ_gốc + χ-K12, bậc 3)")
print(f"\n{'='*65}")
print(f"  BẢNG SO SÁNH TỔNG HỢP")
print(f"{'='*65}")
print(f"  {'|dep|':>8} | {'① Keccak gốc':>13} | {'② chi-K12':>12}")
print(f"  " + "-"*40)
all_k = sorted(set(list(c1)+list(c2)))
for k in all_k:
    print(f"  {k:>8} | {c1.get(k,0):>13,} | {c2.get(k,0):>12,}")
def stats(cnt):
    sizes = sorted(cnt.keys())
    avg = sum(k*v for k,v in cnt.items()) / N
    return sizes[0], sizes[-1], avg
mn1,mx1,avg1 = stats(c1)
mn2,mx2,avg2 = stats(c2)
print(f"  " + "-"*40)
print(f"  {'min':>8} | {mn1:>13} | {mn2:>12}")
print(f"  {'max':>8} | {mx1:>13} | {mx2:>12}")
print(f"  {'avg':>8} | {avg1:>13.1f} | {avg2:>12.1f}")
print(f"  {'vs ①':>8} | {'chuẩn':>13} | {f'×{avg2/avg1:.3f}':>12}")

