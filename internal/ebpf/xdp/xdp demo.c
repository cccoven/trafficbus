//go:build ignore

#include "defs.h"
#include "bpf_helper.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 1024

struct key {
    __u32 srcip;
    __u8 name[10];
};

struct value {
    __u64 packets;
    __u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, struct key);
    __type(value, struct value);
} xdp_map SEC(".maps");

__u32 get_str_len(const char str[]) {
	__u32 len = 0;
	while (str[len] != '\0') {
		len++;
	}
	return len;
}

struct event {
    __u32 id;
    __u8 ids[80];
    __u8 name[10];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} myevents SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {
    // const char fmt_str[] = "Hello, world, from BPF! My PID is %d\n";
    // bpf_trace_printk(fmt_str, sizeof(fmt_str), 111);

    // __u32 k = 100;
    // __u32 *v = bpf_map_lookup_elem(&xdp_map, &k);
    // if (v) {
    //     const char info[] = "[%d]: %d\n";
    //     bpf_trace_printk(info, sizeof(info), k, *v);
    // }

    // char sk[10] = "foo";
    // char sv[10] = "bar";
    // bpf_trace_printk("%s:%s", get_str_len(sk) + get_str_len(sv), sk, sv);
    // bpf_trace_printk("%d", 1, get_str_len(sk));

    // bpf_map_update_elem(&xdp_map, &sk, &sv, BPF_ANY);

    // char v[10] = bpf_map_lookup_elem(&xdp_map, &sk);
    // bpf_trace_printk("%s", 3, v);

    struct key key = {
        .srcip = 123,
        .name = "hello"
    };
    struct value value = {
        .packets = 100,
        .bytes = 1024
    };

    bpf_map_update_elem(&xdp_map, &key, &value, BPF_ANY);
    

    struct event *e;
    e = bpf_ringbuf_reserve(&myevents, sizeof(struct event), 0);
    if (!e) {
        return XDP_PASS;
    }

    e->id = 999;
    e->ids[0] = 1;
    e->ids[1] = 2;
    e->ids[2] = 3;

    e->name[0] = 'h';
    e->name[1] = 'e';
    e->name[2] = 'l';
    e->name[3] = 'l';
    e->name[4] = 'o';

    // e->hobby = sk;
    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}
