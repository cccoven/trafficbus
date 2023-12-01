//go:build ignore

#include "bpf_helper.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_RULES 2

enum protocol {
    TCP = 0,
    UDP,
    ICMP,
};

// common rule
struct xdp_rule {
    u32 num;
    u64 pkts;
    u64 bytes;
    u32 target;
    u32 protocol;
    u32 source;
    u32 source_mask;
    u32 destination;
    u32 destination_mask;
};

// Force emitting enum xdp_action into the ELF.
const enum xdp_action *action __attribute__((unused));
const enum protocol *prot __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct xdp_rule);
} xdp_rule_map SEC(".maps");


struct callback_ctx {
    struct xdp_md *pkt;
    __u32 action;
};

static __u64 callback_fn(void *map, __u32 *key, struct xdp_rule *value, struct callback_ctx *ctx) {
    // const char info[] = "idx: %d, source: %d,  dst: %d\n";
    // bpf_trace_printk(info, sizeof(info), *key, value->source, value->destination);

    if (*key == 0) {
        ctx->action = value->target;

        // end loop
        return 1;
    }
    
    return 0;
}


SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {
    void *data = (void *)(long) ctx->data;
    void *data_end = (void *)(long) ctx->data_end;

    // parse ether header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_ntohl(ETH_P_IP)) {
        // protocol IPv4
        const char debug[] = "ipv4: %d\n";
        bpf_trace_printk(debug, sizeof(debug), eth->h_proto);
    }
        
    struct callback_ctx cb_ctx = {
        .pkt = ctx,
        .action = XDP_PASS,
    };
    bpf_for_each_map_elem(&xdp_rule_map, callback_fn, &cb_ctx, BPF_ANY);

    // const char debug[] = "rule result: %d\n";
    // bpf_trace_printk(debug, sizeof(debug), cb_ctx.action);

    return cb_ctx.action;
}
