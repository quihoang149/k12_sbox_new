#ifndef KECCAKP1600_H
#define KECCAKP1600_H
#include <stdint.h>

typedef uint64_t KeccakState[25]; // A[x][y] = state[x + 5*y]

// CHI_MODE: 0 = chi goc (Keccak chuan), 1 = chi-K12 (de xuat)
extern int CHI_MODE;

void KeccakP1600_Permute_12rounds(KeccakState state);

#endif
