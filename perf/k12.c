// k12.c — Cau truc cay Sakura cua KangarooTwelve, port TRUNG THUC tu code Go
// (kangarootwelve.go + sponge.go) da duoc kiem chung PASS toan bo test vector
// chinh thuc trong qua trinh lam viec truoc do. Chi doi phan permutation (chi).
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "keccakp1600.h"

#define MAX_CHUNK 8192
#define RATE_BYTES 168   // 1344 bit / 8

typedef struct {
    KeccakState a;
    uint8_t buf[RATE_BYTES];
    int buf_len;          // so byte dang cho trong buf (giai doan hap thu)
    int rate;
    uint8_t dsbyte;
    int squeezing;         // 0 = dang hap thu, 1 = dang vat
    int squeeze_pos;        // vi tri da doc trong buf khi vat
} SpongeState;

static void sponge_init(SpongeState *s, uint8_t dsbyte) {
    memset(s->a, 0, sizeof(s->a));
    s->buf_len = 0;
    s->rate = RATE_BYTES;
    s->dsbyte = dsbyte;
    s->squeezing = 0;
    s->squeeze_pos = 0;
}

static void sponge_permute(SpongeState *s) {
    for (int i = 0; i < s->rate; i++)
        ((uint8_t*)s->a)[i] ^= s->buf[i];
    KeccakP1600_Permute_12rounds(s->a);
}

static void sponge_write(SpongeState *s, const uint8_t *p, size_t len) {
    while (len > 0) {
        if (s->buf_len == 0 && len >= (size_t)s->rate) {
            for (int i = 0; i < s->rate; i++)
                ((uint8_t*)s->a)[i] ^= p[i];
            KeccakP1600_Permute_12rounds(s->a);
            p += s->rate; len -= s->rate;
        } else {
            int todo = s->rate - s->buf_len;
            if (todo > (int)len) todo = (int)len;
            memcpy(s->buf + s->buf_len, p, todo);
            s->buf_len += todo;
            p += todo; len -= todo;
            if (s->buf_len == s->rate) {
                sponge_permute(s);
                s->buf_len = 0;
            }
        }
    }
}

static void sponge_pad_and_permute(SpongeState *s) {
    memset(s->buf + s->buf_len, 0, s->rate - s->buf_len);
    s->buf[s->buf_len] = s->dsbyte;
    s->buf[s->rate - 1] ^= 0x80;
    sponge_permute(s);
    s->squeezing = 1;
    s->squeeze_pos = 0;
}

static void sponge_read(SpongeState *s, uint8_t *out, size_t len) {
    if (!s->squeezing) sponge_pad_and_permute(s);
    while (len > 0) {
        int avail = s->rate - s->squeeze_pos;
        int n = avail < (int)len ? avail : (int)len;
        memcpy(out, ((uint8_t*)s->a) + s->squeeze_pos, n);
        s->squeeze_pos += n; out += n; len -= n;
        if (s->squeeze_pos == s->rate) {
            KeccakP1600_Permute_12rounds(s->a);
            s->squeeze_pos = 0;
        }
    }
}

// right_encode theo dung dac ta K12 (khop logic Go da PASS test vector)
static int right_encode(uint64_t value, uint8_t *out) {
    uint8_t tmp[9]; int n = 0;
    if (value != 0) {
        uint64_t v = value;
        uint8_t rev[8]; int k=0;
        while (v > 0) { rev[k++] = (uint8_t)(v & 0xff); v >>= 8; }
        for (int i = k-1; i >= 0; i--) tmp[n++] = rev[i];
    }
    memcpy(out, tmp, n);
    out[n] = (uint8_t)n;
    return n + 1;
}

// Trang thai cay dung chung cho ham tree_write (tuong ung struct treeState cua Go)
typedef struct {
    SpongeState main_s;
    SpongeState chunk_s;
    int numChunk;
    int chunkInited;
    size_t currentWritten;
} K12Tree;

// tree_write: DUNG Y HET logic dinh tuyen cua ham Write() trong Go (kangarootwelve.go).
// QUAN TRONG (LOI DA TIM VA SUA): ham nay phai duoc goi cho CA du lieu chinh LAN
// customString/do dai cua no — vi ca hai deu can di qua CUNG mot co che dinh tuyen
// (ghi vao main hay vao chunk dang mo, tuy numChunk). Ban truoc ghi customString
// THANG vao main_s trong moi truong hop -> dung cho 1-chunk, SAI cho nhieu-chunk
// (da phat hien qua doi chieu debug voi ban Go da PASS test vector chinh thuc).
static void tree_write(K12Tree *t, const uint8_t *p, size_t len) {
    size_t remaining = len;
    while (remaining > 0) {
        if (t->currentWritten == MAX_CHUNK) {
            if (t->numChunk == 0) {
                uint8_t pad[8] = {0x03,0,0,0,0,0,0,0};
                sponge_write(&t->main_s, pad, 8);
            } else {
                uint8_t tmp_out[32];
                sponge_read(&t->chunk_s, tmp_out, 32);
                sponge_write(&t->main_s, tmp_out, 32);
            }
            t->currentWritten = 0;
            t->numChunk++;
            t->chunkInited = 0;
        }
        size_t todo = MAX_CHUNK - t->currentWritten;
        if (todo > remaining) todo = remaining;

        if (t->numChunk == 0) {
            sponge_write(&t->main_s, p, todo);
        } else {
            if (!t->chunkInited) { sponge_init(&t->chunk_s, 0x0b); t->chunkInited = 1; }
            sponge_write(&t->chunk_s, p, todo);
        }
        t->currentWritten += todo;
        p += todo; remaining -= todo;
    }
}

// K12: ham bam chinh, port tu treeState cua Go (kangarootwelve.go)
void K12_Hash(const uint8_t *customString, size_t csLen,
              const uint8_t *data, size_t dataLen,
              uint8_t *hash, size_t hashLen) {
    K12Tree t;
    sponge_init(&t.main_s, 0x07);
    t.numChunk = 0;
    t.chunkInited = 0;
    t.currentWritten = 0;

    tree_write(&t, data, dataLen);

    // customString + do dai cua no: PHAI dung tree_write (khong ghi thang vao main_s)
    tree_write(&t, customString, csLen);
    uint8_t enc[9]; int enc_len = right_encode((uint64_t)csLen, enc);
    tree_write(&t, enc, enc_len);

    if (t.numChunk == 0) {
        t.main_s.dsbyte = 0x07;   // 1 chunk duy nhat
    } else {
        uint8_t tmp_out[32];
        sponge_read(&t.chunk_s, tmp_out, 32);
        sponge_write(&t.main_s, tmp_out, 32);
        uint8_t enc2[9]; int enc2_len = right_encode((uint64_t)t.numChunk, enc2);
        sponge_write(&t.main_s, enc2, enc2_len);
        uint8_t ff[2] = {0xff, 0xff};
        sponge_write(&t.main_s, ff, 2);
        t.main_s.dsbyte = 0x06;   // nhieu chunk
    }

    sponge_read(&t.main_s, hash, hashLen);
}

// ============================================================================
// K12_Hash_Parallel — BAN DA LUONG (OpenMP), tan dung dac diem thiet ke cot loi
// cua KangarooTwelve: cac chunk 8192-byte (tru chunk DAU va chunk CUOI) la HOAN
// TOAN DOC LAP voi nhau, nen co the tinh CV cua chung SONG SONG tren nhieu nhan.
//
// Chien luoc:
//   1. 8192 byte DAU luon di thang vao main state (tuan tu, bat buoc — day la
//      phan "khoi dong" chua the song song).
//   2. Cac chunk DAY DU o giua (chunk thu 2..N-1) — SONG SONG hoa qua OpenMP.
//   3. Chunk CUOI CUNG (co the day du hoac le) va customString — di qua ham
//      tree_write() GOC (tuan tu, TAI SU DUNG nguyen code da kiem chung), de
//      dam bao dung 100% cac truong hop bien (padding, customString dai...).
//
// KET QUA PHAI khop tuyet doi voi K12_Hash — da doi chieu truoc khi su dung
// that su cho benchmark/muc dich khac.
// ============================================================================
#ifdef _OPENMP
#include <omp.h>
#endif

void K12_Hash_Parallel(const uint8_t *customString, size_t csLen,
                        const uint8_t *data, size_t dataLen,
                        uint8_t *hash, size_t hashLen) {
    if (dataLen <= MAX_CHUNK) {
        // Chi 1 chunk -> khong co gi de song song, dung thang ban tuan tu.
        K12_Hash(customString, csLen, data, dataLen, hash, hashLen);
        return;
    }

    size_t restLen = dataLen - MAX_CHUNK;
    int totalChunks = (int)((restLen + MAX_CHUNK - 1) / MAX_CHUNK); // lam tron len
    int numParallel = totalChunks - 1;   // chunk CUOI CUNG luon de lai, khong tinh song song
    if (numParallel < 0) numParallel = 0;

    // ---- PHA SONG SONG: tinh CV cho cac chunk day du o giua ----
    uint8_t (*cvs)[32] = NULL;
    if (numParallel > 0) {
        cvs = malloc((size_t)numParallel * 32);
        #pragma omp parallel for schedule(dynamic)
        for (int c = 0; c < numParallel; c++) {
            SpongeState cs;
            sponge_init(&cs, 0x0b);
            sponge_write(&cs, data + MAX_CHUNK + (size_t)c * MAX_CHUNK, MAX_CHUNK);
            sponge_read(&cs, cvs[c], 32);
        }
    }

    // ---- PHA TUAN TU: ghep noi ket qua, dung lai tree_write() GOC ----
    K12Tree t;
    sponge_init(&t.main_s, 0x07);
    t.numChunk = 0; t.chunkInited = 0; t.currentWritten = 0;

    tree_write(&t, data, MAX_CHUNK);          // 8192 byte dau

    uint8_t pad[8] = {0x03,0,0,0,0,0,0,0};
    sponge_write(&t.main_s, pad, 8);
    t.numChunk = 1;

    for (int c = 0; c < numParallel; c++) {
        sponge_write(&t.main_s, cvs[c], 32);
        t.numChunk++;
    }
    if (cvs) free(cvs);

    // Chunk CUOI CUNG (day du hoac le) -> tree_write GOC, giu "mo" giong sequential
    size_t lastOff = MAX_CHUNK + (size_t)numParallel * MAX_CHUNK;
    size_t lastLen = dataLen - lastOff;
    t.currentWritten = 0;
    tree_write(&t, data + lastOff, lastLen);

    // customString + do dai — dung tree_write GOC (co the tao them chunk neu rat dai)
    tree_write(&t, customString, csLen);
    uint8_t enc[9]; int enc_len = right_encode((uint64_t)csLen, enc);
    tree_write(&t, enc, enc_len);

    uint8_t tmp_out[32];
    sponge_read(&t.chunk_s, tmp_out, 32);
    sponge_write(&t.main_s, tmp_out, 32);
    uint8_t enc2[9]; int enc2_len = right_encode((uint64_t)t.numChunk, enc2);
    sponge_write(&t.main_s, enc2, enc2_len);
    uint8_t ff[2] = {0xff, 0xff};
    sponge_write(&t.main_s, ff, 2);
    t.main_s.dsbyte = 0x06;

    sponge_read(&t.main_s, hash, hashLen);
}
