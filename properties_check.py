N = 5
SIZE = 1 << N

CHI      = [0,5,10,11,20,17,22,23,9,12,3,2,13,8,15,14,18,21,24,27,6,1,4,7,26,29,16,19,30,25,28,31]
CHI_K12  = [31,28,25,24,19,4,17,5,7,1,8,13,3,21,10,30,14,12,2,18,16,22,26,15,6,9,11,23,20,27,29,0]

def parity(v): return bin(v).count("1") & 1
def inverse(S):
    inv=[0]*SIZE
    for x in range(SIZE): inv[S[x]]=x
    return inv

# ---- 1. Bac dai so (algebraic degree) ----
def algebraic_degree(S):
    deg=0
    for b in range(1,SIZE):                     # moi thanh phan b.S
        f=[parity(b & S[x]) for x in range(SIZE)]
        c=f[:]                                   # Mobius transform
        for k in range(N):
            for m in range(SIZE):
                if (m>>k)&1: c[m]^=c[m^(1<<k)]
        d=max((bin(m).count("1") for m in range(SIZE) if c[m]), default=0)
        deg=max(deg,d)
    return deg

# ---- 2. Phi tuyen (nonlinearity) & 4. Xap xi tuyen tinh (linearity = max|LAT|) ----
def walsh_based(S):
    maxW=0
    for b in range(1,SIZE):
        for a in range(SIZE):
            W=sum(1 if parity(a&x)^parity(b&S[x])==0 else -1 for x in range(SIZE))
            maxW=max(maxW,abs(W))
    linearity=maxW//2                            # = max|LAT|
    nonlinearity=(1<<(N-1)) - linearity
    return nonlinearity, linearity

# ---- 3. Vi phan cuc dai (differential uniformity = max DDT, a!=0) ----
def differential_uniformity(S):
    du=0
    for a in range(1,SIZE):
        cnt=[0]*SIZE
        for x in range(SIZE): cnt[S[x]^S[x^a]]+=1
        du=max(du,max(cnt))
    return du

# ---- 5. AC cuc dai (absolute indicator) ----
def absolute_indicator(S):
    best=0
    for b in range(1,SIZE):
        g=[parity(b&S[x]) for x in range(SIZE)]
        for s in range(1,SIZE):
            r=sum(1 if g[x]==g[x^s] else -1 for x in range(SIZE))
            best=max(best,abs(r))
    return best

# ---- 6. Dong nhat BCT (boomerang uniformity = max BCT, a!=0,b!=0) ----
def bct_uniformity(S):
    inv=inverse(S); bu=0
    for a in range(1,SIZE):
        for b in range(1,SIZE):
            cnt=0
            for x in range(SIZE):
                if inv[S[x]^b]^inv[S[x^a]^b]==a: cnt+=1
            bu=max(bu,cnt)
    return bu

# ---- 9. Diem bat dong (fixed points) ----
def fixed_points(S):
    return sum(1 for x in range(SIZE) if S[x]==x)

def all_props(S):
    nl,lin=walsh_based(S)
    return {
        "Bac dai so":            algebraic_degree(S),
        "Phi tuyen":             nl,
        "Vi phan cuc dai":       differential_uniformity(S),
        "Xap xi tuyen tinh":     lin,
        "AC cuc dai":            absolute_indicator(S),
        "Dong nhat BCT":         bct_uniformity(S),
        "Diem bat dong":         fixed_points(S),
    }

pc = all_props(CHI); pk = all_props(CHI_K12)
print(f"{'Tinh chat':<22}{'chi (goc)':>12}{'chi-K12':>12}{'   tot hon':>12}")
print("-"*58)
better_small = {"Vi phan cuc dai","AC cuc dai","Diem bat dong"}   # nho hon = tot
better_big   = {"Bac dai so"}                                      # lon hon = tot
for k in pc:
    c,v=pc[k],pk[k]
    if k in better_small: tag="chi-K12" if v<c else ("chi" if c<v else "bang")
    elif k in better_big: tag="chi-K12" if v>c else ("chi" if c>v else "bang")
    else: tag="bang" if v==c else ("chi-K12" if v<c else "chi")
    print(f"{k:<22}{c:>12}{v:>12}{tag:>12}")
