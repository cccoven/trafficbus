#include <stdio.h>

#define FLAG_FIN (1 << 0) // 00000001
#define FLAG_SYN (1 << 1) // 00000010
#define FLAG_RST (1 << 2) // 00000100
#define FLAG_PSH (1 << 3) // 00001000
#define FLAG_ACK (1 << 4) // 00010000
#define FLAG_URG (1 << 5) // 00100000

int main() {
    int flags = 0;

    flags |= FLAG_SYN;
    flags |= FLAG_ACK;

    if (flags & FLAG_SYN) {
        printf("flag SYN is set\n");
    }

    if (flags & FLAG_ACK) {
        printf("flag ACK is set\n");
    }

    return 0;
}
