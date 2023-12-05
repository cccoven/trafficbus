#include <stdio.h>
#include <stdlib.h>

struct test {
    int a;
};

void set(struct test *t) {
    struct test *t2 = malloc(sizeof(struct test));
    t2->a = 100;
    printf("t2: %d\n", t2->a);
    *t = *t2;
}

int main() {
    struct test t;
    set(&t);
    printf("t: %d\n", t.a);
    return 0;
}
