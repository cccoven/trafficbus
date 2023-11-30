//go:build ignore

#include "defs.h"
#include "bpf_helper.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_RULES 10

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
    __type(key, u32);
    __type(value, struct xdp_rule);
} xdp_rule_map SEC(".maps");

long callback_fn(void *map, const void *key, void *value, void *ctx) {
    const char info[] = "key: %d\n";
    bpf_trace_printk(info, sizeof(info), key);

    return 0;
}

SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {

    // u32 k = 0;
    // struct xdp_rule *rule;
    // rule = bpf_map_lookup_elem(&xdp_rule_map, &k);
    // if (rule) {
    //     const char info[] = " source: %d,  dst: %d\n";
    //     bpf_trace_printk(info, sizeof(info), rule->source, rule->destination);
    // }
    // k = 1;
    // rule = bpf_map_lookup_elem(&xdp_rule_map, &k);
    // if (rule) {
    //     const char info[] = " source: %d,  dst: %d\n";
    //     bpf_trace_printk(info, sizeof(info), rule->source, rule->destination);
    // }

    u32 i;
    struct xdp_rule *rule;
    for (i = 0; i < 1; i++) {
        const char debug[] = "index: %d\n";
        bpf_trace_printk(debug, sizeof(debug), i);

        rule = bpf_map_lookup_elem(&xdp_rule_map, &i);
        if (!rule) {
            continue;
        }

        // const char info[] = " source: %d,  dst: %d\n";
        // bpf_trace_printk(info, sizeof(info), rule->source, rule->destination);
    }

    // u32 i;
    // struct xdp_rule *rule;
    // while (i < MAX_RULES) {
    //     const char debug[] = "index: %d\n";
    //     bpf_trace_printk(debug, sizeof(debug), i);

    //     rule = bpf_map_lookup_elem(&xdp_rule_map, &i);
    //     if (rule) {
    //         const char info[] = " source: %d,  dst: %d\n";
    //         bpf_trace_printk(info, sizeof(info), rule->source, rule->destination);
    //     }
    //     break;
    // }

    // bpf_for_each_map_elem(&xdp_rule_map, callback_fn, , BPF_ANY);

    return XDP_PASS;
}
