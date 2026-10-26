/*
Ban DIEU CHINH cua testPerformance.c (goc: XKCP, tac gia Gilles Van Assche va
Ronny Van Keer) — CHUYEN sang goi K12_Hash() (chi goc / chi-K12) thay vi
KT128/KT256 cua XKCP, va BO toan bo phan phat hien/bao cao SIMD (AVX512,
AVX2, SSSE3, KeccakP1600times2/4/8) vi ban khong co cac cai dat toi uu do —
chi co ban C portable don gian (khong SIMD).

GIU NGUYEN logic do "slope" (do dop) va ky thuat lay MIN cua 100 mau tu
timing.h/timing.c goc — day chinh la phan gia tri nhat cua bo cong cu nay.
*/
#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "align.h"
#include "timing.h"
#include "testPerformance.h"
#include "keccakp1600.h"
#include "k12.h"

#define BIG_BUFFER_SIZE (2*1024*1024)
ALIGN(64) static uint8_t bigBuffer[BIG_BUFFER_SIZE];

// ==================== HAM CAU NOI (adapter) ====================
// Chuyen doi chu ky ham cua K12_Hash() (thu tu tham so KHAC XKCP) sang dung
// chu ky ham ma testPerformanceFull() ben duoi mong doi (giong XKCP goc), de
// tai su dung nguyen logic do "slope" khong can sua gi them.
static int impl_chi_original(const unsigned char *input, size_t inputLen,
                              unsigned char *output, size_t outputLen,
                              const unsigned char *customization, size_t customLen) {
    CHI_MODE = 0;   // chi GOC
    K12_Hash(customization, customLen, input, inputLen, output, outputLen);
    return 0;
}
static int impl_chi_k12(const unsigned char *input, size_t inputLen,
                         unsigned char *output, size_t outputLen,
                         const unsigned char *customization, size_t customLen) {
    CHI_MODE = 1;   // chi-K12 (de xuat)
    K12_Hash(customization, customLen, input, inputLen, output, outputLen);
    return 0;
}

cycles_t measurePerformance(int (*impl)(const unsigned char*, size_t,
                                       unsigned char*, size_t,
                                       const unsigned char*, size_t),
                           cycles_t dtMin, unsigned int inputLen)
{
    ALIGN(64) unsigned char output[32];
    measureTimingDeclare

    assert(inputLen <= BIG_BUFFER_SIZE);

    memset(bigBuffer, 0xA5, 16);

    measureTimingBeginDeclared
    impl(bigBuffer, inputLen, output, 32, (const unsigned char *)"", 0);
    measureTimingEnd
}

// GIU NGUYEN 100% logic quet do dai va tinh "slope" tu ban XKCP goc —
// day la phan quan trong nhat, khong sua gi.
void testPerformanceFull(int (*impl)(const unsigned char*, size_t,
                                     unsigned char*, size_t,
                                     const unsigned char*, size_t), int extra)
{
    const unsigned int chunkSize = 8192;
    unsigned halfTones;
    cycles_t calibration = CalibrateTimer();
    unsigned int chunkSizeLog = (unsigned int)floor(log(chunkSize)/log(2.0)+0.5);
    int displaySlope = 0;

    measurePerformance(impl, calibration, 500000);
    for(halfTones=chunkSizeLog*12-28; halfTones<=13*12; halfTones+=4) {
        double I = pow(2.0, halfTones/12.0);
        unsigned int i  = (unsigned int)floor(I+0.5);
        cycles_t time, timePlus1Block, timePlus2Blocks, timePlus4Blocks, timePlus8Blocks;
        cycles_t timePlus168Blocks;
        time = measurePerformance(impl, calibration, i);
        if (i == chunkSize) {
            displaySlope = 1;
            timePlus1Block  = measurePerformance(impl, calibration, i+1*chunkSize);
            timePlus2Blocks = measurePerformance(impl, calibration, i+2*chunkSize);
            timePlus4Blocks = measurePerformance(impl, calibration, i+4*chunkSize);
            timePlus8Blocks = measurePerformance(impl, calibration, i+8*chunkSize);
            timePlus168Blocks = measurePerformance(impl, calibration, i+extra*chunkSize);
        }
        printf("%8u bytes: %9"PRId64" %s, %6.3f %s/byte\n", i, time, getTimerUnit(), time*1.0/i, getTimerUnit());
        if (displaySlope) {
            printf("     +1 block:  %9"PRId64" %s, %6.3f %s/byte (slope)\n", timePlus1Block, getTimerUnit(), (timePlus1Block-(double)(time))*1.0/chunkSize/1.0, getTimerUnit());
            printf("     +2 blocks: %9"PRId64" %s, %6.3f %s/byte (slope)\n", timePlus2Blocks, getTimerUnit(), (timePlus2Blocks-(double)(time))*1.0/chunkSize/2.0, getTimerUnit());
            printf("     +4 blocks: %9"PRId64" %s, %6.3f %s/byte (slope)\n", timePlus4Blocks, getTimerUnit(), (timePlus4Blocks-(double)(time))*1.0/chunkSize/4.0, getTimerUnit());
            printf("     +8 blocks: %9"PRId64" %s, %6.3f %s/byte (slope)\n", timePlus8Blocks, getTimerUnit(), (timePlus8Blocks-(double)(time))*1.0/chunkSize/8.0, getTimerUnit());
            printf("   +%d blocks: %9"PRId64" %s, %6.3f %s/byte (slope)\n", extra, timePlus168Blocks, getTimerUnit(), (timePlus168Blocks-(double)(time))*1.0/chunkSize/(extra*1.0), getTimerUnit());
            displaySlope = 0;
        }
    }
    for(halfTones=12*12; halfTones<=20*12; halfTones+=4) {
        double I = chunkSize + pow(2.0, halfTones/12.0);
        unsigned int i  = (unsigned int)floor(I+0.5);
        cycles_t time;
        time = measurePerformance(impl, calibration, i);
        printf("%8u bytes: %9"PRId64" %s, %6.3f %s/byte\n", i, time, getTimerUnit(), time*1.0/i, getTimerUnit());
    }
    printf("\n\n");
}

// DA DON GIAN HOA: bo toan bo phan in thong tin SIMD (khong ap dung, vi
// ban dung cai dat C portable, khong co AVX512/AVX2/SSSE3/times2/4/8).
void testPerformance()
{
    printf("*** chi GOC (Keccak chuan) ***\n\n");
    testPerformanceFull(impl_chi_original, 168);

    printf("*** chi-K12 (de xuat) ***\n\n");
    testPerformanceFull(impl_chi_k12, 168);
}
