// keccak_original.c — Keccak CHUAN (SHA3-256 style, Keccak-f[1600], 24 vong, chi GOC).
// Chuong trinh DOC LAP, chi chua DUY NHAT bien the nay (khong co cong tac runtime),
// dung de do kich thuoc bang `size` theo dung tinh than bao cao Ascon-AEAD (moi
// phien ban la mot chuong trinh rieng biet).
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t KeccakState[25];

static inline uint64_t ROL64(uint64_t x, int n) {
    n &= 63;
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

static const int RHO_OFFSET[5][5] = {
    { 0, 36,  3, 41, 18}, { 1, 44, 10, 45,  2}, {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56}, {27, 20, 39,  8, 14},
};

// 24 hang so vong DAY DU (khac K12 chi dung 12 hang so CUOI) — da doi chieu LFSR truoc do.
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
    for (int x = 0; x < 5; x++) C[x] = A(x,0)^A(x,1)^A(x,2)^A(x,3)^A(x,4);
    for (int x = 0; x < 5; x++) D[x] = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) A(x,y) ^= D[x];
}
static void rho(KeccakState state) {
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) A(x,y) = ROL64(A(x,y), RHO_OFFSET[x][y]);
}
static void pi(KeccakState state) {
    uint64_t tmp[25];
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) tmp[x+5*y] = A(x,y);
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) A(x,y) = tmp[((x+3*y)%5) + 5*x];
}
// chi GOC (Keccak chuan): y_i = x_i XOR ((NOT x_{i+1}) AND x_{i+2}) — HARDCODE, khong co cong tac
static void chi(KeccakState state) {
    for (int y = 0; y < 5; y++) {
        uint64_t a0=A(0,y), a1=A(1,y), a2=A(2,y), a3=A(3,y), a4=A(4,y);
        A(0,y) = a0 ^ ((~a1) & a2);
        A(1,y) = a1 ^ ((~a2) & a3);
        A(2,y) = a2 ^ ((~a3) & a4);
        A(3,y) = a3 ^ ((~a4) & a0);
        A(4,y) = a4 ^ ((~a0) & a1);
    }
}
static void iota(KeccakState state, int r) { A(0,0) ^= RC[r]; }

// Keccak-f[1600]: DAY DU 24 VONG (khac K12 chi dung 12 vong)
static void KeccakF1600(KeccakState state) {
    for (int r = 0; r < 24; r++) { theta(state); rho(state); pi(state); chi(state); iota(state, r); }
}

// Sponge chuan SHA3-256: rate=1088 bit (136 byte), capacity=512 bit, domain=0x06 (SHA3), out=32 byte
static void sha3_256(const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    const int rate_bytes = 136;
    KeccakState state; memset(state, 0, sizeof(state));
    uint8_t block[136];
    size_t off = 0;
    while (msg_len - off >= (size_t)rate_bytes) {
        for (int i = 0; i < rate_bytes; i++) ((uint8_t*)state)[i] ^= msg[off+i];
        KeccakF1600(state);
        off += rate_bytes;
    }
    size_t rem = msg_len - off;
    memset(block, 0, rate_bytes);
    memcpy(block, msg+off, rem);
    block[rem] = 0x06;
    block[rate_bytes-1] |= 0x80;
    for (int i = 0; i < rate_bytes; i++) ((uint8_t*)state)[i] ^= block[i];
    KeccakF1600(state);
    memcpy(out, state, 32);
}

static void to_hex(const uint8_t *d, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i=0;i<n;i++){ out[2*i]=hx[d[i]>>4]; out[2*i+1]=hx[d[i]&0xf]; }
    out[2*n]=0;
}

int main(void) {
    // Test vector chinh thuc SHA3-256("") — cong bo boi NIST FIPS 202
    uint8_t out[32]; char hexbuf[70];
    sha3_256((const uint8_t*)"", 0, out);
    to_hex(out, 32, hexbuf);
    const char *expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    int ok = strcmp(hexbuf, expected) == 0;
    printf("SHA3-256(\"\") = %s\n", hexbuf);
    printf("Mong doi     = %s\n", expected);
    printf("[%s]\n", ok ? "PASS" : "FAIL");
    return !ok;
}
