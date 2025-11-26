// test.cpp (변경 없음)
#include <stdio.h>
#include "unhooking.h"

int main() {
    printf("Starting surgical unhooking...\n");

    DWORD dwResult = PerformUnhooking(); // 새 함수 호출

    if (dwResult == 0) { // ERR_SUCCESS == 0
        printf("Unhooking successful or no hooks detected.\n");
    }
    else {
        printf("Unhooking failed. First error code: %lu\n", dwResult);
    }

    getchar();
    return (int)dwResult;
}