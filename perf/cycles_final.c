/*
cycles_final.c — Do cycles/byte, dinh dang dau ra Y HET anh mau ban dau
("sorted cycles" + "cycles per byte (min,median)" + bang Markdown).

Dung CycleTimer() tu timing.h (RDTSC qua ASM) -- ky thuat DA CHUNG MINH on
dinh tren may cua ban qua benchmark.exe (XKCP goc).

MOI: nhan THAM SO DONG LENH de chon bien the, KHONG can sua code/bien dich
lai moi lan doi bien the:
    .\cycles_final.exe chi        -> do chi GOC
    .\cycles_final.exe k12        -> do chi-K12
    .\cycles_final.exe            -> (khong tham so) in huong dan, khong chay

CAI DAT: dat file nay cung thu muc voi timing.h, timing.c, keccakp1600.h/c,
k12.h/c da co san (dung nguyen, khong doi).
CHAY:    gcc -O2 -Wall -o cycles_final.exe cycles_final.c timing.c keccakp1600.c k12.c -lm
         .\cycles_final.exe chi
         .\cycles_final.exe k12
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "timing.h"
#include "keccakp1600.h"
#include "k12.h"

static int cmp_i64(const void *a, const void *b) {
    int64_t x=*(const int64_t*)a, y=*(const int64_t*)b;
    return (x>y)-(x<y);
}

#define TRIALS 16
static const size_t LENS[] = {1, 8, 16, 32, 64, 1536, 2048};
#define N_LENS (int)(sizeof(LENS)/sizeof(LENS[0]))

static void measure(int chi_mode, size_t len, int64_t *out_samples) {
    CHI_MODE = chi_mode;
    uint8_t *data = malloc(len ? len : 1);
    for (size_t i=0;i<len;i++) data[i]=(uint8_t)(i&0xff);
    uint8_t out[32];

    for (int w=0; w<20; w++) K12_Hash(NULL,0,data,len,out,32);   // lam nong

    for (int t=0; t<TRIALS; t++) {
        int64_t c0 = CycleTimer();
        K12_Hash(NULL, 0, data, len, out, 32);
        int64_t c1 = CycleTimer();
        out_samples[t] = c1 - c0;
    }
    qsort(out_samples, TRIALS, sizeof(int64_t), cmp_i64);
    free(data);
}

static void fmt(char *buf, double v) {
    if (v >= 15.0) sprintf(buf, "%.0f", v);
    else           sprintf(buf, "%.1f", v);
}

static void print_usage(const char *prog) {
    printf("Cach dung: %s <bien_the>\n", prog);
    printf("  bien_the:\n");
    printf("    chi   -> do chi GOC (Keccak chuan)\n");
    printf("    k12   -> do chi-K12 (de xuat)\n");
    printf("Vi du:\n");
    printf("  %s chi\n", prog);
    printf("  %s k12\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    int CHI_MODE_SELECT;
    const char *ten_bien_the;
    if (strcmp(argv[1], "chi") == 0) {
        CHI_MODE_SELECT = 0;
        ten_bien_the = "chi goc";
    } else if (strcmp(argv[1], "k12") == 0) {
        CHI_MODE_SELECT = 1;
        ten_bien_the = "chi-K12";
    } else {
        printf("Loi: tham so khong hop le '%s'\n\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    //printf("=== Do cycles/byte cho %s (TRIALS=%d moi do dai) ===\n\n", ten_bien_the, TRIALS);

    int64_t samples[N_LENS][TRIALS];
    double  cpb_min[N_LENS], cpb_med[N_LENS];

    printf("sorted cycles:\n");
    for (int i=0;i<N_LENS;i++) {
        measure(CHI_MODE_SELECT, LENS[i], samples[i]);
        printf("%6zu: ", LENS[i]);
        for (int t=0;t<TRIALS;t++) printf("%lld ", (long long)samples[i][t]);
        printf("\n");

        double minc = (double)samples[i][0] / (double)LENS[i];
        double medc = (double)samples[i][TRIALS/2] / (double)LENS[i];
        cpb_min[i] = minc; cpb_med[i] = medc;
    }

    printf("\ncycles per byte (min,median):\n");
    for (int i=0;i<N_LENS;i++)
        printf("%6zu: %6.1f %6.1f\n", LENS[i], cpb_min[i], cpb_med[i]);

    printf("\n");
    printf("|");
    for (int i=0;i<N_LENS;i++) printf(" %6zu |", LENS[i]);
    printf("\n|");
    for (int i=0;i<N_LENS;i++) printf("--------|");
    printf("\n|");
    for (int i=0;i<N_LENS;i++) {
        char b[16]; fmt(b, cpb_min[i]);
        printf(" %6s |", b);
    }
    printf("\n");

    return 0;
}