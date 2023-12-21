//go:build ignore

#include "bpf_helper.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_RULES 5
#define MAX_IPSET 255

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
    u16 multiport[65535];
};

struct target_ext {};

// common rule
struct xdp_rule {
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

// Force emitting enum xdp_action into the ELF.
const enum target *action __attribute__((unused));
const enum protocol *prot __attribute__((unused));
const enum ipset_direction *ipsetdirectrion __attribute__((unused));

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct ipv4_lpm_val {
    __u32 addr;
    __u32 mask;
};

struct ipset_inner_map {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ipv4_lpm_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} ipset_inner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_IPSET);
    __type(key, __u32); // ipset name(id)
    __array(values, struct ipset_inner_map);
} ipset_map SEC(".maps") = {
    .values = { &ipset_inner_map }
};

struct rule_inner_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct xdp_rule);
} rule_inner_map SEC(".maps"), rule_inner_map2 SEC(".maps");

struct rule_map {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 50);
    __uint(key_size, sizeof(__u32)); // net interface index
    __uint(value_size, 4); // net interface index
    __array(values, struct rule_inner_map);
} rule_map SEC(".maps") = {
    .values = {
        [1] = &rule_inner_map,
        [2] = &rule_inner_map2,
    }
};

struct callback_ctx {
    struct xdp_md *xdp_data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    __u32 action;
};

struct cursor {
    void *pos;
};

static __always_inline int parse_ethhdr(struct cursor *cur, void *data_end, struct ethhdr **eth) {
    struct ethhdr *__eth = cur->pos;
    if ((void *)(__eth + 1) > data_end) {
        return 0;
    }
    int ethhdr_size = sizeof(*__eth);
    *eth = __eth;
    cur->pos += ethhdr_size;
    return 1;
}

static __always_inline int parse_iphdr(struct cursor *cur, void *data_end, struct iphdr **ip) {
    struct iphdr *__ip = cur->pos;
    if ((void *)(__ip + 1) > data_end) {
        return 0;
    }
    int iphdr_size = __ip->ihl * 4;
    *ip = __ip;
    cur->pos += iphdr_size;
    return 1;
}

static __always_inline int parse_udphdr(struct cursor *cur, void *data_end, struct udphdr **udp) {
    struct udphdr *__udp = cur->pos;
    if ((void *)(__udp + 1) > data_end) {
        return 0;
    }
    int udphdr_size = __udp->len;
    *udp = __udp;
    cur->pos += udphdr_size;
    return 1;
}

static __always_inline int parse_tcphdr(struct cursor *cur, void *data_end, struct tcphdr **tcp) {
    struct tcphdr *__tcp = cur->pos;
    if ((void *)(__tcp + 1) > data_end) {
        return 0;
    }
    int tcphdr_size = __tcp->doff * 4;
    *tcp = __tcp;
    cur->pos += tcphdr_size;
    return 1;
}

static int __always_inline match_protocol(__u32 pkt_prot, __u32 rule_prot) {
    // all protocol
    if (!rule_prot) {
        return 1;
    }
    return pkt_prot == rule_prot;
}

static int __always_inline match_ip(__u32 pktip, __u32 ruleip, __u32 ruleip_mask) {
    if (!ruleip) { 
        // all address
        return 1;
    }

    // match CIDR
    if (ruleip_mask) {
        return (ruleip & ruleip_mask) == (pktip & ruleip_mask);
    }

    return pktip == ruleip;
}

static int __always_inline match_udp(struct udphdr *udp, struct xdp_rule *rule) {
    struct udp_ext udpext = rule->match_ext.udp;
    if (!udpext.enable) {
        return 1;
    }
    if (udpext.sport && bpf_htons(udp->source) != udpext.sport) {
        return 0;
    }
    if (udpext.dport && bpf_htons(udp->dest) != udpext.dport) {
        return 0;
    }

    return 1;
}

static int __always_inline match_tcp(struct tcphdr *tcp, struct xdp_rule *rule) {
    struct tcp_ext tcpext = rule->match_ext.tcp;
    if (!tcpext.enable) {
        return 1;
    };
    if (tcpext.sport && bpf_htons(tcp->source) != tcpext.sport) {
        return 0;
    }
    if (tcpext.dport && bpf_htons(tcp->dest) != tcpext.dport) {
        return 0;
    }

    return 1;
}

// match rules
static __u64 traverse_rules(void *map, __u32 *key, struct xdp_rule *rule, struct callback_ctx *ctx) {
    // __bpf_printk("index: %u, target: %u, protocol: %u", *key, rule->target, rule->protocol);
    if (!rule->enable) {
        return 1;
    }

    __bpf_printk("index: %u, target: %u, protocol: %u", *key, rule->target, rule->protocol);
    return 0;

    if (ctx->ip) {
        int hitprot = match_protocol(ctx->ip->protocol, rule->protocol);
        if (!hitprot) {
            // go to the next rule
            return 0;
        }

        int hitsip = match_ip(bpf_htonl(ctx->ip->saddr), rule->source, rule->source_mask);
        int hitdip = match_ip(bpf_htonl(ctx->ip->daddr), rule->destination, rule->destination_mask);
        if (!hitsip || !hitdip) {
            return 0;
        }
    }

    int hit = 0;
    switch (rule->protocol) {
        case IPPROTO_ICMP:
            // TODO
            ctx->action = rule->target;
            hit = 1;
            break;
        case IPPROTO_UDP:
            if (ctx->udp && (hit = match_udp(ctx->udp, rule))) {
                ctx->action = rule->target;
            }
            break;
        case IPPROTO_TCP:
            if (ctx->tcp && (hit = match_tcp(ctx->tcp, rule))) {
                ctx->action = rule->target;
            }
            break;
        default:
            // support empty rule
            ctx->action = rule->target;
            hit = 1;
            break;
    }

    // __bpf_printk("matched rule num: %d", rule->num);
    
    return hit;
}

struct test {
    struct xdp_rule rules[10];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct test);
} test_map SEC(".maps");

SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {

    __u32 key = ctx->ingress_ifindex;
    struct test *test = bpf_map_lookup_elem(&test_map, &key);
    if (test) {
        for (int i = 0; i < sizeof(test->rules) / sizeof(struct xdp_rule); i++) {
            struct xdp_rule rule = test->rules[i];
            if (!rule.enable) {
                break;
            }
            __bpf_printk("index: %u, target: %u, protocol: %u", i, rule.target, rule.protocol);
        }
        
        // __bpf_printk("sizeof: %d", sizeof(test->rules) / sizeof(struct xdp_rule));
    }

    return XDP_PASS;

    struct rule_map *outermap = &rule_map;
    __u32 outerkey = ctx->ingress_ifindex;
    // __u32 outerkey = 0;
    struct rule_inner_map *innermap = bpf_map_lookup_elem(outermap, &outerkey);
    // no rules for this interface
    if (!innermap) {
        __bpf_printk("iface %u has no rules", outerkey);
        return XDP_PASS;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct cursor cur = { .pos = data };
    struct callback_ctx cbstack = {
        .xdp_data = ctx,
        .action = XDP_PASS,
    };

    struct ethhdr *eth;
    if (!parse_ethhdr(&cur, data_end, &eth)) {
        goto done;
    }
    cbstack.eth = eth;

    // make sure it's IPv4
    if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        goto done;
    }

    struct iphdr *ip;
    if (!parse_iphdr(&cur, data_end, &ip)) {
        goto done;
    }
    cbstack.ip = ip;

    if (ip->protocol == IPPROTO_ICMP) {
        // TODO
    }
 
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        if (!parse_udphdr(&cur, data_end, &udp)) {
            goto done;
        }
        cbstack.udp = udp;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        if (!parse_tcphdr(&cur, data_end, &tcp)) {
            goto done;
        }
        cbstack.tcp = tcp;
    }

    bpf_for_each_map_elem(innermap, traverse_rules, &cbstack, BPF_ANY);

done:
    return cbstack.action;
}
