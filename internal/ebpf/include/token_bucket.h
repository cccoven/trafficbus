#include "defs.h"

struct bucket {
    u64 start_moment;
    u64 capacity;
    u64 quantum;
    u32 fill_interval;
    u64 available_tokens;
    u64 last_tick;
};

static __u64 tb_take_available(struct bucket *bucket, __u64 count) {
    return 0;
}

static __u64 tb_available(struct bucket *bucket) {
    return 0;
}
