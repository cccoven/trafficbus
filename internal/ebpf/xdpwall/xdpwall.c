//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_IP_SET_ENTRIES 1024
#define MAX_IP_SET 100
#define MAX_RULE_SET_ENTRIES 1024
#define MAX_RULE_SET 100

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
struct rule_item {
    u64 pkts;
    u64 bytes;
    enum target target;
    enum protocol protocol;
    u32 source;
    u32 source_mask;
    u32 destination;
    u32 destination_mask;

    struct match_ext match_ext;
    struct target_ext target_ext;
};

struct ip_item {
    __u32 addr;
    __u32 mask;
};

struct ip_set {
    struct ip_item items[MAX_IP_SET];
    int count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_SET_ENTRIES);
    __type(key, __u32);
    __type(value, struct ip_set);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_set_map SEC(".maps");

struct rule_set {
    struct rule_item items[MAX_RULE_SET];
    int count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULE_SET_ENTRIES);
    __type(key, __u32);
    __type(value, struct rule_set);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rule_set_map SEC(".maps");

// Force emitting into the ELF.
const enum target *action __attribute__((unused));
const enum protocol *prot __attribute__((unused));
const enum ip_set_direction *ipsetdirectrion __attribute__((unused));
const struct ip_item *ipsetitem __attribute__((unused));
const struct rule_item *ruleitem __attribute__((unused));
const struct match_ext *matchext __attribute__((unused));
const struct set_ext *setext __attribute__((unused));
const struct udp_ext *udpext __attribute__((unused));
const struct tcp_ext *tcpext __attribute__((unused));
const struct target_ext *targetext __attribute__((unused));

struct pktstack {
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

static int __always_inline match_set(struct iphdr *ip, struct set_ext set_ext) {
    if (!set_ext.id) {
        return 1;
    }

    struct ip_set *ip_set = bpf_map_lookup_elem(&ip_set_map, &set_ext.id);
    if (!ip_set || !ip_set->count) {
        return 1;
    }

    for (int i = 0; i < MAX_IP_SET; i++) {
        if (i >= ip_set->count) {
            break;
        }
        struct ip_item item = ip_set->items[i];
        
        // TODO match set
        switch (set_ext.direction) {
            case SRC:
                match_ip(bpf_htonl(ip->saddr), item.addr, item.mask);
                break;
            case DST:
                match_ip(bpf_htonl(ip->daddr), item.addr, item.mask);
                break;
            case BOTH:
                break;
            default:
                break;
        }
    }
    
    return 1;
}

static int __always_inline match_udp(struct udphdr *udp, struct rule_item *rule) {
    struct udp_ext udpext = rule->match_ext.udp;
    if (udpext.sport && bpf_htons(udp->source) != udpext.sport) {
        return 0;
    }
    if (udpext.dport && bpf_htons(udp->dest) != udpext.dport) {
        return 0;
    }

    return 1;
}

static int __always_inline match_tcp(struct tcphdr *tcp, struct rule_item *rule) {
    struct tcp_ext tcpext = rule->match_ext.tcp;
    if (tcpext.sport && bpf_htons(tcp->source) != tcpext.sport) {
        return 0;
    }
    if (tcpext.dport && bpf_htons(tcp->dest) != tcpext.dport) {
        return 0;
    }

    return 1;
}

static __always_inline int traverse_rule(struct rule_set *rule_set, struct pktstack *pkt) {
    for (int i = 0; i < MAX_RULE_SET; i++) {
        if (i >= rule_set->count) {
            break;
        }
        struct rule_item rule = rule_set->items[i];

        int hitprot = match_protocol(pkt->ip->protocol, rule.protocol);
        if (!hitprot) {
            continue;
        }

        int hitsip = match_ip(bpf_htonl(pkt->ip->saddr), rule.source, rule.source_mask);
        int hitdip = match_ip(bpf_htonl(pkt->ip->daddr), rule.destination, rule.destination_mask);
        if (!hitsip || !hitdip) {
            continue;
        }

        int hitset = match_set(pkt->ip, rule.match_ext.set);
        if (!hitset) {
            continue;
        }

        int hit;
        switch (rule.protocol) {
            case IPPROTO_ICMP:
                // TODO
                hit = 1;
                break;
            case IPPROTO_UDP:
                if (pkt->udp) {
                    hit = match_udp(pkt->udp, &rule);
                }
                break;
            case IPPROTO_TCP:
                if (pkt->tcp) {
                    hit = match_tcp(pkt->tcp, &rule);
                }
                break;
            default:
                // support empty rule
                hit = 1;
                break;
        }

        if (!hit) {
            continue;
        };

        pkt->action = rule.target;
        return hit;
    }

    return 0;
}

SEC("xdp")
int xdp_wall_func(struct xdp_md *ctx) {
    __u32 key = ctx->ingress_ifindex;
    struct rule_set *rule = bpf_map_lookup_elem(&rule_set_map, &key);
    if (!rule || !rule->count) {
        return XDP_PASS;
    }
    
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct cursor cur = { .pos = data };
    struct pktstack pkt = {
        .action = ACCEPT,
    };

    if (!parse_ethhdr(&cur, data_end, &pkt.eth)) {
        goto done;
    }

    // make sure it's ipv4, for now
    if (pkt.eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        goto done;
    }

    if (!parse_iphdr(&cur, data_end, &pkt.ip)) {
        goto done;
    }

     if (pkt.ip->protocol == IPPROTO_ICMP) {
        // TODO parse icmp header
    }

    if (pkt.ip->protocol == IPPROTO_UDP) {
        if (!parse_udphdr(&cur, data_end, &pkt.udp)) {
            goto done;
        }
    }

    if (pkt.ip->protocol == IPPROTO_TCP) {
        if (!parse_tcphdr(&cur, data_end, &pkt.tcp)) {
            goto done;
        }
    }

    if (traverse_rule(rule, &pkt)) {
        return pkt.action;
    }

done:
    return pkt.action;
}
