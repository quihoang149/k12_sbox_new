#ifndef K12_H
#define K12_H
#include <stdint.h>
#include <stddef.h>

void K12_Hash(const uint8_t *customString, size_t csLen,
              const uint8_t *data, size_t dataLen,
              uint8_t *hash, size_t hashLen);

// Ban DA LUONG (OpenMP): song song hoa viec tinh CV cua cac chunk DOC LAP.
// Ket qua PHAI khop tuyet doi voi K12_Hash (da kiem chung bang cach doi chieu
// tren nhieu kich thuoc du lieu khac nhau truoc khi su dung).
void K12_Hash_Parallel(const uint8_t *customString, size_t csLen,
                        const uint8_t *data, size_t dataLen,
                        uint8_t *hash, size_t hashLen);

#endif
