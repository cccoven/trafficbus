//go:build ignore

#include "bpf_helper.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_RULES 5

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
    struct udp_ext udp;
    struct tcp_ext tcp;
    u16 multiport[65535];
};

struct target_ext {};

// common rule
struct xdp_rule {
    int enable;
    u32 num;
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct xdp_rule);
} xdp_rule_map SEC(".maps");

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
    if (!rule->enable) {
        return 1;
    }

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
            if (ctx->udp) {
                __bpf_printk("dip: %u, dport: %u", ctx->ip->daddr, ctx->udp->dest);
            }
            if (ctx->udp && (hit = match_udp(ctx->udp, rule))) {
                ctx->action = rule->target;

                // rewriting
                __bpf_printk("before dip: %u, dport: %u", ctx->ip->daddr, ctx->udp->dest);

                // ctx->ip->saddr = bpf_htonl(3232238818);
                ctx->ip->daddr = bpf_htonl(3232238818);
                ctx->udp->dest = bpf_htons(8082);
                
                __bpf_printk("after dip: %u, dport: %u", ctx->ip->daddr, ctx->udp->dest);
                return bpf_redirect(0, BPF_ANY);
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

SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {
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

    bpf_for_each_map_elem(&xdp_rule_map, traverse_rules, &cbstack, BPF_ANY);

done:
    return cbstack.action;
}
