//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_IPS 5000
#define MAX_IPSET 5000
#define MAX_RULES 5000

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

enum ip_set_direction {
    SRC = 1,
    DST,
    BOTH,
};

struct set_ext {
    u32 id;
    enum ip_set_direction direction;
};

// example: -p udp --dport 8080
struct udp_ext {
    u16 sport;
    u16 dport;
};

struct tcp_ext {
    u16 sport;
    u16 dport;
};

// example: -m comment --comment "foo"
struct match_ext {
    struct set_ext set;
    struct udp_ext udp;
    struct tcp_ext tcp;
    u16 multiport;
};

struct target_ext {};

// common rule
struct rule {
    int interface;
    enum target target;
    enum protocol protocol;
    u32 source;
    u32 source_mask;
    u32 destination;
    u32 destination_mask;
    
    struct match_ext match_ext;
    struct target_ext target_ext;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct ipv4_lpm_val {
    __u32 data;
    __u32 set_ids[MAX_IPSET];
    __u32 set_masks[MAX_IPSET];
    int cur;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_IPS);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipset_map SEC(".maps");

struct ipset_item {
    __u32 id;
    __u32 ip;
    __u32 mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_IPS);
    __type(key, __u32);
    __type(value, struct ipset_item);
} ipset_map2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct rule);
} rule_map SEC(".maps");

// Force emitting into the ELF.
const enum target *action __attribute__((unused));
const enum protocol *prot __attribute__((unused));
const enum ip_set_direction *ipsetdirectrion __attribute__((unused));

struct cbstack {
    int index;
    struct xdp_md *raw;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    enum target action;
};

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

static int __always_inline match_udp(struct udphdr *udp, struct rule *rule) {
    struct udp_ext udpext = rule->match_ext.udp;
    if (udpext.sport && bpf_htons(udp->source) != udpext.sport) {
        return 0;
    }
    if (udpext.dport && bpf_htons(udp->dest) != udpext.dport) {
        return 0;
    }

    return 1;
}

static int __always_inline match_tcp(struct tcphdr *tcp, struct rule *rule) {
    struct tcp_ext tcpext = rule->match_ext.tcp;
    if (tcpext.sport && bpf_htons(tcp->source) != tcpext.sport) {
        return 0;
    }
    if (tcpext.dport && bpf_htons(tcp->dest) != tcpext.dport) {
        return 0;
    }

    return 1;
}

static int __always_inline match_set(struct iphdr *ip, struct set_ext setext) {
    // not set
    if (!setext.id) {
        return 1;
    }

    struct ipv4_lpm_key key = { .prefixlen = 32 };
    if (setext.direction == SRC) {
        key.data = bpf_htonl(ip->saddr);
    }
    if (setext.direction == DST) {
        key.data = bpf_htonl(ip->daddr);
    }
    
    __u32 *val = bpf_map_lookup_elem(&ipset_map, &key);
    if (val) {
        __bpf_printk("hit ipset: %u", *val);
    }

    return val ? 1 : 0;
}

static __u64 traverse_rules(void *map, __u32 *key, struct rule *rule, struct cbstack *ctx) {
    // exit
    if (!rule->interface) return 1;
    // go to next
    if (rule->interface != ctx->raw->ingress_ifindex) return 0;
    ctx->index = *key;

    // __bpf_printk("index: %d, prot: %d", ctx->index, rule->protocol);

    if (!match_protocol(ctx->ip->protocol, rule->protocol)) {
        return 0;
    }

    int hitsip = match_ip(bpf_htonl(ctx->ip->saddr), rule->source, rule->source_mask);
    int hitdip = match_ip(bpf_htonl(ctx->ip->daddr), rule->destination, rule->destination_mask);
    if (!hitsip || !hitdip) {
        return 0;
    }

    if (!match_set(ctx->ip, rule->match_ext.set)) {
        return 0;
    }

    int hittprot;
    switch (rule->protocol) {
        case IPPROTO_ICMP:
            // TODO
            hittprot = 1;
            break;
        case IPPROTO_UDP:
            if (ctx->udp) hittprot = match_udp(ctx->udp, rule);
            break;
        case IPPROTO_TCP:
            if (ctx->tcp) hittprot = match_tcp(ctx->tcp, rule);
            break;
        default:
            // support empty rule
            hittprot = 1;
            break;
    }

    if (hittprot) {
        ctx->action = rule->target;
        return 1;
    }

    return 0;
}

SEC("xdp")
int xdp_wall_func(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct cursor cur = { .pos = data };
    struct cbstack stack = { 
        .index = 0,
        .raw = ctx,
        .action = ACCEPT,
    };

    struct ethhdr *eth; 
    if (!parse_ethhdr(&cur, data_end, &eth)) {
        goto out;
    }
    stack.eth = eth;

    // make sure it's ipv4, for now
    if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        goto out;
    }

    struct iphdr *ip;
    if (!parse_iphdr(&cur, data_end, &ip)) {
        goto out;
    }
    stack.ip = ip;

    struct udphdr *udp;
    struct tcphdr *tcp;
    switch (ip->protocol) {
        case IPPROTO_ICMP:
            // TODO parse icmp header
            break;
        case IPPROTO_UDP:
            if (!parse_udphdr(&cur, data_end, &udp)) {
                goto out;
            }
            stack.udp = udp;
            break;
        case IPPROTO_TCP:
            // struct tcphdr *tcp;
            if (!parse_tcphdr(&cur, data_end, &tcp)) {
                goto out;
            }
            stack.tcp = tcp;
            break;
    }

    bpf_for_each_map_elem(&rule_map, &traverse_rules, &stack, BPF_ANY);

out:
    return stack.action;
}
