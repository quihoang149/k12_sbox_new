// kangarootwelve_original.c — KangarooTwelve VOI CHI GOC (khong phai chi-K12).
// Chuong trinh DOC LAP, khong co cong tac runtime (CHI_MODE) — chi hardcode chi GOC.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef uint64_t KeccakState[25];
static inline uint64_t ROL64(uint64_t x, int n) { n&=63; return n==0?x:(x<<n)|(x>>(64-n)); }
static const int RHO_OFFSET[5][5] = {
    { 0, 36,  3, 41, 18}, { 1, 44, 10, 45,  2}, {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56}, {27, 20, 39,  8, 14},
};
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
    for (int x=0;x<5;x++) C[x]=A(x,0)^A(x,1)^A(x,2)^A(x,3)^A(x,4);
    for (int x=0;x<5;x++) D[x]=C[(x+4)%5]^ROL64(C[(x+1)%5],1);
    for (int x=0;x<5;x++) for (int y=0;y<5;y++) A(x,y)^=D[x];
}
static void rho(KeccakState state){ for(int x=0;x<5;x++) for(int y=0;y<5;y++) A(x,y)=ROL64(A(x,y),RHO_OFFSET[x][y]); }
static void pi(KeccakState state){
    uint64_t tmp[25];
    for(int x=0;x<5;x++) for(int y=0;y<5;y++) tmp[x+5*y]=A(x,y);
    for(int x=0;x<5;x++) for(int y=0;y<5;y++) A(x,y)=tmp[((x+3*y)%5)+5*x];
}
// chi GOC — HARDCODE, khong co bien the khac trong file nay
static void chi(KeccakState state) {
    for (int y=0;y<5;y++) {
        uint64_t a0=A(0,y),a1=A(1,y),a2=A(2,y),a3=A(3,y),a4=A(4,y);
        A(0,y)=a0^((~a1)&a2); A(1,y)=a1^((~a2)&a3); A(2,y)=a2^((~a3)&a4);
        A(3,y)=a3^((~a4)&a0); A(4,y)=a4^((~a0)&a1);
    }
}
static void iota(KeccakState state,int r){ A(0,0)^=RC[r]; }
static void KeccakP1600_12(KeccakState state) {
    for (int r=12;r<24;r++) { theta(state); rho(state); pi(state); chi(state); iota(state,r); }
}

#define MAX_CHUNK 8192
#define RATE_BYTES 168
typedef struct {
    KeccakState a; uint8_t buf[RATE_BYTES]; int buf_len; uint8_t dsbyte;
    int squeezing; int squeeze_pos;
} SpongeState;
static void sponge_init(SpongeState *s, uint8_t dsbyte) {
    memset(s->a,0,sizeof(s->a)); s->buf_len=0; s->dsbyte=dsbyte; s->squeezing=0; s->squeeze_pos=0;
}
static void sponge_permute(SpongeState *s) {
    for (int i=0;i<RATE_BYTES;i++) ((uint8_t*)s->a)[i]^=s->buf[i];
    KeccakP1600_12(s->a);
}
static void sponge_write(SpongeState *s, const uint8_t *p, size_t len) {
    while (len>0) {
        if (s->buf_len==0 && len>=(size_t)RATE_BYTES) {
            for (int i=0;i<RATE_BYTES;i++) ((uint8_t*)s->a)[i]^=p[i];
            KeccakP1600_12(s->a); p+=RATE_BYTES; len-=RATE_BYTES;
        } else {
            int todo=RATE_BYTES-s->buf_len; if (todo>(int)len) todo=(int)len;
            memcpy(s->buf+s->buf_len,p,todo); s->buf_len+=todo; p+=todo; len-=todo;
            if (s->buf_len==RATE_BYTES) { sponge_permute(s); s->buf_len=0; }
        }
    }
}
static void sponge_pad_and_permute(SpongeState *s) {
    memset(s->buf+s->buf_len,0,RATE_BYTES-s->buf_len);
    s->buf[s->buf_len]=s->dsbyte; s->buf[RATE_BYTES-1]|=0x80;
    sponge_permute(s); s->squeezing=1; s->squeeze_pos=0;
}
static void sponge_read(SpongeState *s, uint8_t *out, size_t len) {
    if (!s->squeezing) sponge_pad_and_permute(s);
    while (len>0) {
        int avail=RATE_BYTES-s->squeeze_pos; int n=avail<(int)len?avail:(int)len;
        memcpy(out,((uint8_t*)s->a)+s->squeeze_pos,n);
        s->squeeze_pos+=n; out+=n; len-=n;
        if (s->squeeze_pos==RATE_BYTES) { KeccakP1600_12(s->a); s->squeeze_pos=0; }
    }
}
static int right_encode(uint64_t value, uint8_t *out) {
    uint8_t tmp[9]; int n=0;
    if (value!=0) { uint64_t v=value; uint8_t rev[8]; int k=0;
        while(v>0){rev[k++]=(uint8_t)(v&0xff);v>>=8;}
        for(int i=k-1;i>=0;i--) tmp[n++]=rev[i]; }
    memcpy(out,tmp,n); out[n]=(uint8_t)n; return n+1;
}
typedef struct { SpongeState main_s, chunk_s; int numChunk, chunkInited; size_t currentWritten; } K12Tree;
static void tree_write(K12Tree *t, const uint8_t *p, size_t len) {
    size_t remaining=len;
    while (remaining>0) {
        if (t->currentWritten==MAX_CHUNK) {
            if (t->numChunk==0) { uint8_t pad[8]={0x03,0,0,0,0,0,0,0}; sponge_write(&t->main_s,pad,8); }
            else { uint8_t tmp_out[32]; sponge_read(&t->chunk_s,tmp_out,32); sponge_write(&t->main_s,tmp_out,32); }
            t->currentWritten=0; t->numChunk++; t->chunkInited=0;
        }
        size_t todo=MAX_CHUNK-t->currentWritten; if (todo>remaining) todo=remaining;
        if (t->numChunk==0) sponge_write(&t->main_s,p,todo);
        else { if(!t->chunkInited){sponge_init(&t->chunk_s,0x0b);t->chunkInited=1;} sponge_write(&t->chunk_s,p,todo); }
        t->currentWritten+=todo; p+=todo; remaining-=todo;
    }
}
void K12_Hash(const uint8_t *customString, size_t csLen, const uint8_t *data, size_t dataLen,
              uint8_t *hash, size_t hashLen) {
    K12Tree t; sponge_init(&t.main_s,0x07); t.numChunk=0; t.chunkInited=0; t.currentWritten=0;
    tree_write(&t,data,dataLen);
    tree_write(&t,customString,csLen);
    uint8_t enc[9]; int enc_len=right_encode((uint64_t)csLen,enc);
    tree_write(&t,enc,enc_len);
    if (t.numChunk==0) t.main_s.dsbyte=0x07;
    else {
        uint8_t tmp_out[32]; sponge_read(&t.chunk_s,tmp_out,32); sponge_write(&t.main_s,tmp_out,32);
        uint8_t enc2[9]; int enc2_len=right_encode((uint64_t)t.numChunk,enc2); sponge_write(&t.main_s,enc2,enc2_len);
        uint8_t ff[2]={0xff,0xff}; sponge_write(&t.main_s,ff,2); t.main_s.dsbyte=0x06;
    }
    sponge_read(&t.main_s,hash,hashLen);
}

static void to_hex(const uint8_t *d, size_t n, char *out) {
    static const char hx[]="0123456789abcdef";
    for (size_t i=0;i<n;i++){ out[2*i]=hx[d[i]>>4]; out[2*i+1]=hx[d[i]&0xf]; }
    out[2*n]=0;
}

int main(void) {
    // Test vector K12 chinh thuc: K12(M="",C="",32 byte)
    uint8_t out[32]; char hexbuf[70];
    K12_Hash(NULL, 0, (const uint8_t*)"", 0, out, 32);
    to_hex(out, 32, hexbuf);
    const char *expected = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5";
    int ok = strcmp(hexbuf, expected) == 0;
    printf("K12(\"\",\"\",32B) = %s\n", hexbuf);
    printf("Mong doi        = %s\n", expected);
    printf("[%s]\n", ok ? "PASS" : "FAIL");
    return !ok;
}
