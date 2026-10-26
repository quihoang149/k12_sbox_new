// align.h — ban toi gian, chi cung cap macro ALIGN can cho testPerformance.c
// (thay the align.h day du cua XKCP goc, khong can toan bo tinh nang cua ho).
#ifndef _ALIGN_H_
#define _ALIGN_H_

#if defined(_MSC_VER)
#define ALIGN(n) __declspec(align(n))
#else
#define ALIGN(n) __attribute__((aligned(n)))
#endif

#endif
