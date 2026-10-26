/*
Ban DON GIAN HOA cua main.c (goc: XKCP) — BO loi goi testKangarooTwelve()
(kiem tra dung dan kieu KAT cua XKCP, ban KHONG co ha tang do) vi ban da co
bo kiem tra rieng (k12test.exe, PASS 13/13 vector chinh thuc). File nay
CHI con lai phan benchmark hieu nang (testPerformance()).
*/
#include <stdio.h>
#include <string.h>
#include "testPerformance.h"

void printHelp()
{
    printf("Cach dung: benchmark.exe [tuy chon]\n");
    printf("  --help hoac -h     Hien trang nay\n");
    printf("  --speed hoac -s    Do hieu nang (chi goc va chi-K12)\n");
}

int main(int argc, char* argv[])
{
    int speed = 0, help = 0;

    if (argc <= 1) speed = 1;   // mac dinh: chay benchmark neu khong co tham so
    for (int i = 1; i < argc; i++) {
        if (strcmp("--help", argv[i]) == 0 || strcmp("-h", argv[i]) == 0) help = 1;
        else if (strcmp("--speed", argv[i]) == 0 || strcmp("-s", argv[i]) == 0) speed = 1;
        else { printf("Khong nhan dien duoc lenh '%s'\n", argv[i]); return -1; }
    }
    if (help) { printHelp(); return 0; }
    if (speed) testPerformance();
    return 0;
}
