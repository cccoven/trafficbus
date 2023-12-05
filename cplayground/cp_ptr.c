#include <stdio.h>
#include <stdlib.h>

struct test {
    int a;
};

void set_t(struct test *t3) {
    printf("t3_inter=%p\n", t3); // initially，t3 and t3_inter point to the same address
    struct test *t4 = malloc(sizeof(struct test));
    t3 = t4; // this is not the expected point t3 to t4
             // it changes the original pointer of t3
    printf("t4=%p\tt3=%p\n", t4, t3); // now t3 and t4 point to the same address
}

int main() {
    int *a = malloc(sizeof(int));
    *a = 100;
    int *b = a;
    *b = 200;
    printf("a=%p\tb=%p\n", a, b); // point to the same address

    struct test *t = malloc(sizeof(struct test));
    t->a = 100;
    struct test *t2 = t;
    printf("t=%p\tt2=%p\n", t, t2); // point to the same address

    struct test *t3 = malloc(sizeof(struct test));
    printf("t3=%p\t", t3);
    set_t(t3);
    printf("t3=%p\n", t3); // in the end, t3 here is still maintains the original pointer

    return 0;
}
