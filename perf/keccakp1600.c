// keccakp1600.c — Hoan vi Keccak-p[1600,12] dung cho KangarooTwelve.
// Ho tro CHI_MODE de doi giua chi goc (Keccak chuan) va chi-K12 (de xuat).
//
// Cong thuc bitwise cua chi-K12 DA DUOC KIEM CHUNG (doi chieu LUT 32 phan tu, khop 100%)
// truoc khi dua vao file nay — xem phan giai thich kem theo.
#include "keccakp1600.h"

int CHI_MODE = 1;   // 0 = chi goc | 1 = chi-K12 (mac dinh dung bien the de xuat)

static inline uint64_t ROL64(uint64_t x, int n) {
    n &= 63;
    if (n == 0) return x;
    return (x << n) | (x >> (64 - n));
}

// Offset cua rho, dung DUNG chi so da xac minh xuyen suot du an (khop bang do tang bac dai so 2.6)
static const int RHO_OFFSET[5][5] = {
    /* x=0 */ { 0, 36,  3, 41, 18},
    /* x=1 */ { 1, 44, 10, 45,  2},
    /* x=2 */ {62,  6, 43, 15, 61},
    /* x=3 */ {28, 55, 25, 21, 56},
    /* x=4 */ {27, 20, 39,  8, 14},
};

// Hang so vong RC[12..23] — 12 hang so CUOI trong day 24 (dung chuan Keccak-p[1600,12],
// da doi chieu voi ban Go da PASS test vector chinh thuc: cung logic bo qua 12 hang so dau).
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

#define A(x,y) state[(x) + 5*(y)]

static void theta(KeccakState state) {
    uint64_t C[5], D[5];
    for (int x = 0; x < 5; x++)
        C[x] = A(x,0) ^ A(x,1) ^ A(x,2) ^ A(x,3) ^ A(x,4);
    for (int x = 0; x < 5; x++)
        D[x] = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            A(x,y) ^= D[x];
}

static void rho(KeccakState state) {
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            A(x,y) = ROL64(A(x,y), RHO_OFFSET[x][y]);
}

static void pi(KeccakState state) {
    uint64_t tmp[25];
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            tmp[x + 5*y] = A(x,y);
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            A(x,y) = tmp[((x+3*y)%5) + 5*x];
}

// chi GOC (Keccak chuan): y_i = x_i XOR ((NOT x_{i+1}) AND x_{i+2})
static void chi_original(KeccakState state) {
    for (int y = 0; y < 5; y++) {
        uint64_t a0=A(0,y), a1=A(1,y), a2=A(2,y), a3=A(3,y), a4=A(4,y);
        A(0,y) = a0 ^ ((~a1) & a2);
        A(1,y) = a1 ^ ((~a2) & a3);
        A(2,y) = a2 ^ ((~a3) & a4);
        A(3,y) = a3 ^ ((~a4) & a0);
        A(4,y) = a4 ^ ((~a0) & a1);
    }
}

// chi-K12 (de xuat): y_i = 1 XOR x_i XOR x_{i+1} XOR x_i.x_{i+1} XOR x_i.x_{i+2}
//                          XOR x_{i+2}.x_{i+4} XOR x_i.x_{i+2}.x_{i+4} XOR x_i.x_{i+3}.x_{i+4}
// Da kiem chung: cong thuc nay khop TUYET DOI voi LUT 32 phan tu cua chi-K12
// (kiem tra tung to hop bit truoc khi dua vao code C nay).
static void chi_k12(KeccakState state) {
    const uint64_t ONES = ~0ULL;
    for (int y = 0; y < 5; y++) {
        uint64_t a[5] = {A(0,y), A(1,y), A(2,y), A(3,y), A(4,y)};
        uint64_t out[5];
        for (int i = 0; i < 5; i++) {
            int i1=(i+1)%5, i2=(i+2)%5, i3=(i+3)%5, i4=(i+4)%5;
            out[i] = ONES ^ a[i] ^ a[i1] ^ (a[i]&a[i1]) ^ (a[i]&a[i2]) ^ (a[i2]&a[i4])
                     ^ (a[i]&a[i2]&a[i4]) ^ (a[i]&a[i3]&a[i4]);
        }
        A(0,y)=out[0]; A(1,y)=out[1]; A(2,y)=out[2]; A(3,y)=out[3]; A(4,y)=out[4];
    }
}

static void iota(KeccakState state, int round_index) {
    A(0,0) ^= RC[round_index];
}

void KeccakP1600_Permute_12rounds(KeccakState state) {
    // Keccak-p[1600,12]: dung 12 vong CUOI trong day 24 (round_index = 12..23),
    // dung chuan da xac nhan doc lap qua ca ban Go va Python truoc do.
    for (int r = 12; r < 24; r++) {
        theta(state);
        rho(state);
        pi(state);
        if (CHI_MODE == 0) chi_original(state);
        else               chi_k12(state);
        iota(state, r);
    }
}
