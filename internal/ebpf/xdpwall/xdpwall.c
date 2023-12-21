//go:build ignore

#include "bpf_helper.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";


#define MAX_IPSET_ENTRIES 1024
#define MAX_IPSET 255
#define MAX_RULES_ENTRIES 1024
#define MAX_RULES 100

enum target {
    ABORTED = XDP_ABORTED,
    DROP = XDP_DROP,
    ACCEPT = XDP_PASS,
    TX = XDP_TX,
    FORWARD = XDP_REDIRECT,
    LOG,
};

enum protocol {
    ICMP = IPPROTO_ICMP,
    UDP = IPPROTO_UDP,
    TCP = IPPROTO_TCP,
};

enum ipset_direction {
    SRC,
    DST,
};

struct set_ext {
    int enable;
    u32 id;
    int direction;
};

// example: -p udp --dport 8080
struct udp_ext {
    int enable;
    u16 sport;
    u16 dport;
};

struct tcp_ext {
    int enable;
    u16 sport;
    u16 dport;
};

// example: -m comment --comment "foo"
struct match_ext {
    int enable;
    struct set_ext set;
    struct udp_ext udp;
    struct tcp_ext tcp;
    u16 multiport;
};

struct target_ext {};

// common rule
struct rule_item {
    int enable;
    u64 pkts;
    u64 bytes;
    u32 target;
    u32 protocol;
    u32 source;
    u32 source_mask;
    u32 destination;
    u32 destination_mask;

    struct match_ext match_ext;
    struct target_ext target_ext;
};

struct ipset_item {
    __u32 addr;
    __u32 mask;
};

struct ipsets {
    struct ipset_item items[MAX_IPSET];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IPSET_ENTRIES);
    __type(key, __u32);
    __type(value, struct ipsets);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipset_map SEC(".maps");

struct rules {
    struct rule_item items[MAX_RULES];
    int count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES_ENTRIES);
    __type(key, __u32);
    __type(value, struct rules);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rule_map SEC(".maps");

// Force emitting into the ELF.
const enum target *action __attribute__((unused));
const enum protocol *prot __attribute__((unused));
const enum ipset_direction *ipsetdirectrion __attribute__((unused));
const struct ipset_item *ipsetitem __attribute__((unused));
const struct rule_item *ruleitem __attribute__((unused));

SEC("xdp")
int xdp_wall_func(struct xdp_md *ctx) {
    __u32 key = ctx->ingress_ifindex;
    struct rules *rules = bpf_map_lookup_elem(&rule_map, &key);
    if (!rules) {
        return XDP_PASS;
    }
    
    // __bpf_printk("count: %d", rules->count);

    for (int i = 0; i < MAX_RULES; i++) {
        struct rule_item rule = rules->items[i];
        if (!rule.enable) {
            break;
        }
        __bpf_printk("protocol: %u", rule.protocol);
    }

    return XDP_PASS;
}
