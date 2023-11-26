//go:build ignore

#include "defs.h"
#include "bpf_helper.h"

char __license[] SEC("license") = "Dual MIT/GPL";

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#define MAX_MAP_ENTRIES 16

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} xdp_map SEC(".maps");

__u32 get_str_len(const char str[]) {
	__u32 len = 0;
	while (str[len] != '\0') {
		len++;
	}
	return len;
}

struct event {
    u32 id;
    u8 ids[80];
    u8 name[10];
    // u8 hobby[100];
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

    __u32 k = 100;
    __u32 *v = bpf_map_lookup_elem(&xdp_map, &k);

    if (v) {
        const char info[] = "[%d]: %d\n";
        // bpf_trace_printk(info, sizeof(info), k, *v);
    }

    // char sk[10] = "foo";
    // char *sv = "bar";
    // char sv[10] = "bar";
    
    // bpf_trace_printk("%s:%s", get_str_len(sk) + get_str_len(sv), sk, sv);

    // bpf_map_update_elem(&xdp_str_map, sk, &sv, BPF_ANY);

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
