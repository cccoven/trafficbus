//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_IPS 200
#define MAX_IPSET 1024
#define MAX_RULES 4096

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

struct ip_item {
    s16 enable;
    u32 addr;
    u32 mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IPSET);
    __type(key, __u32);
    __uint(value_size, sizeof(struct ip_item) * MAX_IPS);
} ip_set_map SEC(".maps");

struct set_ext {
    s16 enable;
    u32 id;
    enum ip_set_direction direction;
};

// example: -p udp --dport 8080
struct udp_ext {
    s16 enable;
    u16 sport;
    u16 dport;
};

struct tcp_ext {
    s16 enable;
    u16 sport;
    u16 dport;
};

struct ip_pair {
    u16 port;
    u16 max;
};

struct multi_port_ext {
    s16 enable;
    int src_size;
    int dst_size;
    struct ip_pair src[10];
    struct ip_pair dst[10];
};

// example: -m comment --comment "foo"
struct match_ext {
    s16 enable;
    struct set_ext set;
    struct udp_ext udp;
    struct tcp_ext tcp;
    struct multi_port_ext multi_port;
};

struct target_ext {};

// common rule
struct rule {
    s16 enable;
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct rule);
} rule_map SEC(".maps");

struct match_event {
    int rule_index;
    u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} match_events SEC(".maps");

// Force emitting into the ELF.
const enum target *target_t __attribute__((unused));
const enum protocol *protocol_t __attribute__((unused));
const enum ip_set_direction *ip_set_directrion_t __attribute__((unused));
const struct ip_item *ip_item_t __attribute__((unused));
const struct match_event *match_event_t __attribute__((unused));

struct cbstack {
    int index;
    struct xdp_md *raw;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    enum target action;
    int hit;
};

static int __always_inline match_protocol(__u32 pkt_prot, __u32 rule_prot) {
    // all protocol
    if (!rule_prot) {
        return 1;
    }
    return pkt_prot == rule_prot;
}

static int __always_inline match_ip(__u32 pktip, __u32 ruleip, __u32 ruleip_mask) {
    // all address (0.0.0.0)
    if (!ruleip) { 
        return 1;
    }

    // match CIDR
    if (ruleip_mask) {
        return (ruleip & ruleip_mask) == (pktip & ruleip_mask);
    }

    return pktip == ruleip;
}

static int __always_inline match_udp(struct udphdr *udp, struct udp_ext *ext) {
    // `port == 0` means that port is not set
    int hits = !ext->sport || bpf_htons(udp->source) == ext->sport;
    int hitd = !ext->dport || bpf_htons(udp->dest) == ext->dport;

    return hits && hitd;
}

static int __always_inline match_tcp(struct tcphdr *tcp, struct tcp_ext *ext) {
    // `port == 0` means that port is not set
    int hits = !ext->sport || bpf_htons(tcp->source) == ext->sport;
    int hitd = !ext->dport || bpf_htons(tcp->dest) == ext->dport;

    return hits && hitd;
}

static int __always_inline match_set(struct iphdr *ip, struct set_ext setext) {
    struct ip_item *val = bpf_map_lookup_elem(&ip_set_map, &setext.id);
    if (!val) {
        return 0;
    }

    for (int i = 0; i < MAX_IPS; i++) {
        struct ip_item item = val[i];
        if (!item.enable) {
            break;
        }

        switch (setext.direction) {
            case SRC:
                if (match_ip(bpf_htonl(ip->saddr), item.addr, item.mask)) return 1;
                break;
            case DST:
                if (match_ip(bpf_htonl(ip->daddr), item.addr, item.mask)) return 1;
                break;
            case BOTH:
                if (
                    match_ip(bpf_htonl(ip->saddr), item.addr, item.mask) && 
                    match_ip(bpf_htonl(ip->daddr), item.addr, item.mask)
                ) {
                    return 1;
                }
                break;
        }
    }
    
    return 0;
}

static int __always_inline match_multi_port(u16 sport, u16 dport, struct multi_port_ext ext) {
    __bpf_printk("sport: %u, dport: %u", sport, dport);
    return 1;
}

static __u64 traverse_rules(void *map, __u32 *key, struct rule *rule, struct cbstack *ctx) {
    if (!rule->enable) return 1;

    ctx->index = *key;

    if (rule->interface && rule->interface != ctx->raw->ingress_ifindex) {
        return 0;
    }

    // __bpf_printk("index: %d, prot: %d", ctx->index, rule->protocol);

    if (!match_protocol(ctx->ip->protocol, rule->protocol)) {
        return 0;
    }

    if (
        !match_ip(bpf_htonl(ctx->ip->saddr), rule->source, rule->source_mask) || 
        !match_ip(bpf_htonl(ctx->ip->daddr), rule->destination, rule->destination_mask)
    ) {
        return 0;
    }

    // hit the basic rule here
    ctx->hit = 1;
    if (!rule->match_ext.enable) {    
        ctx->action = rule->target;
        return 1;
    }

    // match extensions
    struct match_ext ext = rule->match_ext;
    // ip set
    if (ext.set.enable && !(ctx->hit = match_set(ctx->ip, ext.set))) {
        return 0;
    }

    int sport, dport;
    // match protocol
    switch (rule->protocol) {
        case IPPROTO_ICMP:
            // TODO
            break;
        case IPPROTO_UDP:
            if (ctx->udp) {
                if (ext.udp.enable && !(ctx->hit = match_udp(ctx->udp, &ext.udp))) {
                    return 0;
                }
                sport = bpf_htons(ctx->udp->source);
                dport = bpf_htons(ctx->udp->dest);
            }
            break;
        case IPPROTO_TCP:
            if (ctx->tcp) {
                if (ext.tcp.enable && !(ctx->hit = match_tcp(ctx->tcp, &ext.tcp))) {
                    return 0;
                }
                sport = bpf_htons(ctx->tcp->source);
                dport = bpf_htons(ctx->tcp->dest);
            }
            break;
        default:
            // support empty rule
            break;
    }

    if (ext.multi_port.enable && !(ctx->hit = match_multi_port(sport, dport, ext.multi_port))) {
        return 0;
    }

    if (ctx->hit) {
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
        .hit = 0,
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
            if (!parse_tcphdr(&cur, data_end, &tcp)) {
                goto out;
            }
            stack.tcp = tcp;
            break;
    }

    bpf_for_each_map_elem(&rule_map, &traverse_rules, &stack, BPF_ANY);

    if (stack.hit) {
        // send match event
        struct match_event *evt = bpf_ringbuf_reserve(&match_events, sizeof(struct match_event), BPF_ANY);
        if (!evt) {
            goto out;
        }
        evt->rule_index = stack.index;
        evt->bytes = data_end - data;
        bpf_ringbuf_submit(evt, BPF_ANY);
    }

out:
    return stack.action;
}
