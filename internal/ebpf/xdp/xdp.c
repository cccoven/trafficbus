//go:build ignore

#include "defs.h"
#include "bpf_helper.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_TABLE 4
#define MAX_CHAINS 1
#define MAX_RULES 1

#define TABLE_NAT 1
#define TABLE_FILTER 2

const char CHAIN_PREROUTING[20] = "PREROUTING";
const char CHAIN_INPUT[20] = "INPUT";
const char CHAIN_FORWARD[20] =  "FORWARD";
const char CHAIN_OUTPUT[20] = "OUTPUT";
const char CHAIN_POSTROUTING[20] = "POSTROUTING";

struct rule {
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

struct chain {
    u8 name[20];
    struct rule rules[MAX_RULES];
};

struct table {
    struct chain chains[MAX_CHAINS];
};

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, MAX_CHAINS);
//     __type(key, u8[20]);
//     __type(value, struct chain);
// } chain_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CHAINS);
    __type(key, u8[20]);
    __type(value, u32);
} table_map SEC(".maps");

SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {

    // u32 k = TABLE_NAT;
    // u32 *v = bpf_map_lookup_elem(&table_map, &k);
    // if (v) {
    //     const char info[] = "[%d]: %d\n";
    //     bpf_trace_printk(info, sizeof(info), k, *v);
    // }

    u32 *v = bpf_map_lookup_elem(&table_map, &CHAIN_PREROUTING);
    if (v) {
        const char info[] = "[%s]: %d\n";
        bpf_trace_printk(info, sizeof(info), CHAIN_PREROUTING, *v);
    }
    
    return XDP_PASS;
}
