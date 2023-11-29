//go:build ignore

#include "defs.h"
#include "bpf_helper.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 4
#define MAX_RULES 10

struct rule_nat {
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
};

struct nat {
    struct rule_nat prerouting[MAX_RULES];
    struct rule_nat postrouting[MAX_RULES];
};

struct rule_filter {
    u32 protocol;
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
    u32 target;
};

struct filter {
    struct rule_filter input[MAX_RULES];
    struct rule_filter output[MAX_RULES];
};

struct modules {
    struct nat nat;
    struct filter filter;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    
} xdp_map SEC(".maps");

SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {
    
    return XDP_PASS;
}
