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

// tracking packet pointer
struct cursor {
    void *pos;
};

struct pktstack {
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    enum xdp_action action;
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

static int __always_inline match_udp(struct udphdr *udp, struct rule_item *rule) {
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

static int __always_inline match_tcp(struct tcphdr *tcp, struct rule_item *rule) {
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

static __always_inline int traverse_rules(struct rules *rules, struct pktstack *pkt) {
    for (int i = 0; i < MAX_RULES; i++) {
        struct rule_item rule = rules->items[i];
        if (!rule.enable) {
            continue;
        }
        
        int hitprot = match_protocol(pkt->ip->protocol, rule.protocol);
        if (!hitprot) {
            continue;
        }

        int hitsip = match_ip(bpf_htonl(pkt->ip->saddr), rule.source, rule.source_mask);
        int hitdip = match_ip(bpf_htonl(pkt->ip->daddr), rule.destination, rule.destination_mask);
        if (!hitsip || !hitdip) {
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
    struct rules *rules = bpf_map_lookup_elem(&rule_map, &key);
    if (!rules || !rules->count) {
        return XDP_PASS;
    }
    
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct cursor cur = { .pos = data };
    struct pktstack pkt = {
        .action = XDP_PASS,
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

    if (traverse_rules(rules, &pkt)) {
        return pkt.action;
    }

done:
    return pkt.action;
}
