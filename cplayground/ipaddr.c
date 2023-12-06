#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

int main() {
    uint32_t uaddr = 16777343;

    struct in_addr addr;

    printf("%d\n", ntohl(uaddr));
    printf("%d\n", ntohs(uaddr));
    printf("%d\n", htons(uaddr));
    printf("%d\n", htonl(uaddr));

    return 0;
}
