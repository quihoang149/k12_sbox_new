import hashlib
import random
W = 64  # Keccak-f[1600]
RHO = {(0,0):0,(0,1):36,(0,2):3,(0,3):41,(0,4):18,(1,0):1,(1,1):44,(1,2):10,(1,3):45,(1,4):2,
       (2,0):62,(2,1):6,(2,2):43,(2,3):15,(2,4):61,(3,0):28,(3,1):55,(3,2):25,(3,3):21,(3,4):56,
       (4,0):27,(4,1):20,(4,2):39,(4,3):8,(4,4):14}

K12 = [31,28,25,24,19,4,17,5,7,1,8,13,3,21,10,30,14,12,2,18,16,22,26,15,6,9,11,23,20,27,29,0]
CHI = [0,5,10,11,20,17,22,23,9,12,3,2,13,8,15,14,18,21,24,27,6,1,4,7,26,29,16,19,30,25,28,31]

# --- sinh hang so vong theo dung thuat toan LFSR chuan cua Keccak (khong hardcode hex) ---
def rc_bit(t):
    if t % 255 == 0: return 1
    R = [1,0,0,0,0,0,0,0]
    for _ in range(1, t % 255 + 1):
        R = [0] + R
        R[0] ^= R[8]; R[4] ^= R[8]; R[5] ^= R[8]; R[6] ^= R[8]
        R = R[:8]
    return R[0]

def round_constants(nrounds=24):
    RC = []
    for rnd in range(nrounds):
        rc = 0
        for j in range(7):
            rc |= rc_bit(j + 7*rnd) << ((1 << j) - 1)
        RC.append(rc)
    return RC

RC = round_constants(24)
# --- kiem tra doi chieu 2 hang so vong dau tien (gia tri chuan da cong bo rong rai) ---
assert RC[0] == 0x0000000000000001, f"RC[0] sai: {hex(RC[0])}"
assert RC[1] == 0x0000000000008082, f"RC[1] sai: {hex(RC[1])}"
print("Kiem tra hang so vong: RC[0]=1, RC[1]=0x8082 -> KHOP chuan Keccak.")

# --- state bieu dien: list 1600 bit, chi so state[x][y][z], x,y in 0..4, z in 0..63 ---
def bits_to_state(bits):
    S = [[[0]*W for _ in range(5)] for _ in range(5)]
    idx = 0
    for x in range(5):
        for y in range(5):
            for z in range(W):
                S[x][y][z] = bits[idx]; idx += 1
    return S
def state_to_bits(S):
    out = []
    for x in range(5):
        for y in range(5):
            for z in range(W):
                out.append(S[x][y][z])
    return out

def theta(S):
    C = [[S[x][y][z] for z in range(W)] for x in range(5) for y in [0]]
    C = [[S[x][0][z]^S[x][1][z]^S[x][2][z]^S[x][3][z]^S[x][4][z] for z in range(W)] for x in range(5)]
    D = [[C[(x-1)%5][z]^C[(x+1)%5][(z-1)%W] for z in range(W)] for x in range(5)]
    return [[[S[x][y][z]^D[x][z] for z in range(W)] for y in range(5)] for x in range(5)]

def rho(S):
    return [[[S[x][y][(z-RHO[(x,y)])%W] for z in range(W)] for y in range(5)] for x in range(5)]

def pi_(S):
    AP = [[[0]*W for _ in range(5)] for _ in range(5)]
    for x in range(5):
        for y in range(5):
            AP[x][y] = S[(x+3*y)%5][x]
    return AP

def chi(S, lut):
    AC_ = [[[0]*W for _ in range(5)] for _ in range(5)]
    for y in range(5):
        for z in range(W):
            a = 0
            for x in range(5): a = (a<<1) | S[x][y][z]     # x0=MSB, dung quy uoc da xac minh
            b = lut[a]
            for x in range(5): AC_[x][y][z] = (b >> (4-x)) & 1
    return AC_

def iota(S, rnd):
    rcv = RC[rnd]
    for z in range(W):
        S[0][0][z] ^= (rcv >> z) & 1     # bit z cua RC (chuan LSB-first cho lane)
    return S

def keccak_p(bits, lut, nrounds, total_rounds=24):
    """Keccak-p[1600, nrounds]: dung nrounds vong CUOI trong day 24 hang so vong chuan
       (dung quy uoc chinh thuc cua ho Keccak-p khi giam so vong, vd KangarooTwelve
       = Keccak-p[1600,12] dung RC[12..23], khong phai RC[0..11])."""
    start = total_rounds - nrounds
    S = bits_to_state(bits)
    for r in range(start, total_rounds):
        S = theta(S); S = rho(S); S = pi_(S); S = chi(S, lut); S = iota(S, r)
    return state_to_bits(S)

def keccak_f(bits, lut, nrounds):
    """Keccak-f[1600] day du: dung nrounds vong DAU (RC[0..nrounds-1])."""
    S = bits_to_state(bits)
    for r in range(nrounds):
        S = theta(S); S = rho(S); S = pi_(S); S = chi(S, lut); S = iota(S, r)
    return state_to_bits(S)

def avalanche_test_p(lut, nrounds, total_rounds=24, trials=200, seed=0):
    """Avalanche cho Keccak-p[1600,nrounds] (dung offset hang so vong nhu keccak_p)."""
    rng = random.Random(seed)
    total_ratio = 0.0
    for _ in range(trials):
        bits = [rng.randint(0,1) for _ in range(1600)]
        flip = rng.randrange(1600)
        bits2 = bits[:]; bits2[flip] ^= 1
        out1 = keccak_p(bits, lut, nrounds, total_rounds)
        out2 = keccak_p(bits2, lut, nrounds, total_rounds)
        dfb = sum(a!=b for a,b in zip(out1,out2))
        total_ratio += dfb / 1600
    return total_ratio / trials * 100

def avalanche_test(lut, nrounds, trials=200, seed=0):
    rng = random.Random(seed)
    total_ratio = 0.0
    for _ in range(trials):
        bits = [rng.randint(0,1) for _ in range(1600)]
        flip = rng.randrange(1600)
        bits2 = bits[:]; bits2[flip] ^= 1
        out1 = keccak_f(bits, lut, nrounds)
        out2 = keccak_f(bits2, lut, nrounds)
        dfb = sum(a!=b for a,b in zip(out1,out2))
        total_ratio += dfb / 1600
    return total_ratio / trials * 100   # AC (%) theo cong thuc 2.4



TRIALS_KECCAK = 300   # so lan thu cho ho Keccak (permutation 1600-bit, nen vua phai vi cham)
TRIALS_HASH   = 2000  # so lan thu cho MD5/SHA-256 (rat nhanh nho hashlib, thu nhieu cho on dinh)

def avalanche_hash(hash_ctor, digest_bits, msg_len_bytes=64, trials=2000, seed=0):
    """AC = DFB/TB x100% cho ham bam chuan (dung hashlib, dam bao dung thuat toan that)."""
    rng = random.Random(seed)
    total_ratio = 0.0
    tb = digest_bits
    for _ in range(trials):
        msg = bytearray(rng.getrandbits(8) for _ in range(msg_len_bytes))
        fb = rng.randrange(msg_len_bytes); bit = rng.randrange(8)
        msg2 = bytearray(msg); msg2[fb] ^= (1 << bit)
        h1 = hash_ctor(bytes(msg)).digest()
        h2 = hash_ctor(bytes(msg2)).digest()
        dfb = sum(bin(a ^ b).count("1") for a, b in zip(h1, h2))
        total_ratio += dfb / tb
    return total_ratio / trials * 100

if __name__ == "__main__":
    print("Dang tinh AC cho 4 he Keccak (permutation 1600-bit, co the mat vai chuc giay)...")
    ko = avalanche_test(CHI, 24, trials=TRIALS_KECCAK, seed=1)
    kk = avalanche_test(K12, 24, trials=TRIALS_KECCAK, seed=1)
    po = avalanche_test_p(CHI, 12, trials=TRIALS_KECCAK, seed=1)
    pk = avalanche_test_p(K12, 12, trials=TRIALS_KECCAK, seed=1)

    print("Dang tinh AC cho MD5, SHA-256 (dung hashlib chuan, rat nhanh)...")
    md5_ac    = avalanche_hash(hashlib.md5,    128, trials=TRIALS_HASH, seed=2)
    sha256_ac = avalanche_hash(hashlib.sha256, 256, trials=TRIALS_HASH, seed=3)

    rows = [
        ("Keccak goc (chi chuan)",           "Keccak-f[1600], 24 vong",       ko),
        ("Keccak + chi-K12 de xuat",         "Keccak-f[1600], 24 vong",       kk),
        ("KangarooTwelve goc",               "Keccak-p[1600,12], 12 vong",    po),
        ("KangarooTwelve + chi-K12 de xuat", "Keccak-p[1600,12], 12 vong",    pk),
        ("MD5",                              "digest 128-bit",                md5_ac),
        ("SHA-256 (SHA-2)",                  "digest 256-bit",                sha256_ac),
    ]

    print()
    print("=" * 78)
    print("BANG SO SANH AC (Avalanche Criterion) O VONG/DIGEST CUOI CUNG")
    print("=" * 78)
    print(f"{'He mat':<34}{'Cau hinh':<26}{'AC (%)':>9}{'Lech':>9}")
    print("-" * 78)
    for name, cfg, ac in rows:
        print(f"{name:<34}{cfg:<26}{ac:>9.3f}{abs(ac-50):>9.3f}")
    print("-" * 78)
    print("Ly tuong AC = 50.000%  (dung mot nua so bit dau ra doi khi lat 1 bit dau vao)")
    print("(MD5, SHA-256 do o muc digest dau ra; ho Keccak do o muc trang thai 1600-bit noi bo)")
