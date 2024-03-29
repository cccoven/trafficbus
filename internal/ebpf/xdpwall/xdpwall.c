//go:build ignore

#include "bpf_endian.h"
#include "parser.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_IPS 200
#define MAX_IPSET 1024
#define MAX_RULES 4096
#define MAX_PORT_PAIRS 10

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

enum tcp_flag {
    SYN = (1 << 0),
    ACK = (1 << 1),
    PSH = (1 << 2),
    URG = (1 << 3),
    FIN = (1 << 4),
    RST = (1 << 5),
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
    u16 src;
    u16 dst;
};

struct tcp_flags {
    int mask;
    int comp;
};

struct tcp_ext {
    s16 enable;
    u16 src;
    u16 dst;
    struct tcp_flags flags;
};

struct port_pair {
    u16 port;
    u16 max;
};

struct multi_port_pairs {
    s16 enable;
    struct port_pair data[MAX_PORT_PAIRS];
};

struct multi_port_ext {
    struct multi_port_pairs src;
    struct multi_port_pairs dst;
};

// example: -m comment --comment "foo"
struct match_ext {
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
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct rule);
} rule_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct match_ext);
} match_ext_map SEC(".maps");

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
const enum tcp_flag *tcp_flag_t __attribute__((unused));
const struct ip_item *ip_item_t __attribute__((unused));
const struct set_ext *set_ext_t __attribute__((unused));
const struct udp_ext *udp_ext_t __attribute__((unused));
const struct tcp_ext *tcp_ext_t __attribute__((unused));
const struct tcp_flags *tcp_flags_t __attribute__((unused));
const struct multi_port_ext *multi_port_ext_t __attribute__((unused));
const struct multi_port_pairs *multi_port_pairs_t __attribute__((unused));
const struct port_pair *port_pair_t __attribute__((unused));
const struct match_event *match_event_t __attribute__((unused));
const struct target_ext *target_ext_t __attribute__((unused));

struct cbstack {
    int index;
    struct xdp_md *raw;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    enum target action;
    __s16 hit;
};

// token bucket
struct bucket {
    u64 start_moment;
    u64 capacity;
    u64 quantum;
    u64 fill_interval;
    u64 available_tokens;
    u64 latest_tick;
};

// calculate how many token filling cycles have elapsed from the start time
static __u64 tb_current_tick(struct bucket *tb) {
    return (bpf_ktime_get_ns() - tb->start_moment) / tb->fill_interval;
}

static void tb_adjust_available(struct bucket *tb, __u64 tick) {
    __u64 latest_tick = tb->latest_tick;
    tb->latest_tick = tick;
    if (tb->available_tokens >= tb->capacity) {
        return;
    }
    tb->available_tokens += (tick - latest_tick) * tb->quantum;
    if (tb->available_tokens > tb->capacity) {
        tb->available_tokens = tb->capacity;
    }
}

static __u64 tb_take_available(struct bucket *tb, __u64 count) {
    if (count <= 0) return 0;
    tb_adjust_available(tb, tb_current_tick(tb));
    if (tb->available_tokens <= 0) {
        return 0;
    }
    if (count >= tb->available_tokens) {
        count = tb->available_tokens;
    }
    tb->available_tokens -= count;
    return count;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct bucket);
} bucket_map SEC(".maps");

static __s16 __always_inline match_protocol(__u32 pkt_prot, __u32 rule_prot) {
    // all protocol
    if (!rule_prot) {
        return 1;
    }
    return pkt_prot == rule_prot;
}

static __s16 __always_inline match_ip(__u32 pktip, __u32 ruleip, __u32 ruleip_mask) {
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

static __s16 __always_inline match_udp(struct udphdr *udp, struct udp_ext *ext) {
    // `port == 0` means that port is not set
    if (ext->src && bpf_htons(udp->source) != ext->src) {
        return 0;
    }
    if (ext->dst && bpf_htons(udp->dest) != ext->dst) {
        return 0;
    }
    
    return 1;
}

static __s16 __always_inline match_tcp(struct tcphdr *tcp, struct tcp_ext *ext) {
    // `port == 0` means that port is not set
    if (ext->src && bpf_htons(tcp->source) != ext->src) {
        return 0;
    }
    if (ext->dst && bpf_htons(tcp->dest) != ext->dst) {
        return 0;
    }

    if (ext->flags.mask && ext->flags.comp) {
        int intersection = ext->flags.mask & ext->flags.comp;
        int difference = ext->flags.mask & (~intersection);

        int flags[6] = {SYN, ACK, PSH, URG, FIN, RST};
        __u16 pkt_flags[6] = {tcp->syn, tcp->ack, tcp->psh, tcp->urg, tcp->fin, tcp->rst};

        for (int i = 0; i < 6; i++) {
            // this flag must be in the mask.
            // constraints should be made in userspace.
            if (!(flags[i] & ext->flags.mask)) {
                return 0;
            }

            // make sure this comp flag is 1
            int comp = (intersection & flags[i]) && !pkt_flags[i];
            // make sure this mask flag is 0
            int mask = (difference & flags[i]) && pkt_flags[i];
            if (comp || mask) {
                return 0;
            }
        }
    }

    return 1;
}

static __s16 __always_inline match_set(struct iphdr *ip, struct set_ext setext) {
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

static __s16 __always_inline match_multi_port(u16 port, struct multi_port_pairs *pairs) {
    __s16 hit = 0;
    for (int i = 0; i < MAX_PORT_PAIRS; i++) {
        struct port_pair pair = pairs->data[i];
        if (!pair.port) {
            break;
        }

        // if `max` is not zero, then this pair is a port range
        hit = pair.max ? (port >= pair.port && port <= pair.max) : (port == pair.port);
        if (hit) {
            break;
        }
    }
    
    return hit;
}

static __s16 __always_inline within_limit(__u32 *key) {
    struct bucket *tb;
    tb = bpf_map_lookup_elem(&bucket_map, key);
    // no limit for this rule
    if (!tb) {
        return 1;
    }
    u64 count = tb_take_available(tb, 1);
    // __bpf_printk("take: %u, remain: %u", count, tb->available_tokens);
    return count;
}

static __u64 traverse_rules(void *map, __u32 *key, struct rule *rule, struct cbstack *ctx) {
    if (!rule->enable) return 1;

    ctx->index = *key;

    if (rule->interface && rule->interface != ctx->raw->ingress_ifindex) {
        return 0;
    }

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
    struct match_ext *ext = bpf_map_lookup_elem(&match_ext_map, key);
    if (!ext) {
        ctx->action = rule->target;
        return 1;
    }

    if (ext->set.enable && !(ctx->hit = match_set(ctx->ip, ext->set))) {
        return 0;
    }

    // match protocol
    switch (rule->protocol) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
            if (ctx->udp) {
                if (ext->udp.enable && !(ctx->hit = match_udp(ctx->udp, &ext->udp))) return 0;
                if (ext->multi_port.src.enable && !(ctx->hit = match_multi_port(bpf_htons(ctx->udp->source), &ext->multi_port.src))) return 0;
                if (ext->multi_port.dst.enable && !(ctx->hit = match_multi_port(bpf_htons(ctx->udp->dest), &ext->multi_port.dst))) return 0;
            }
            break;
        case IPPROTO_TCP:
            if (ctx->tcp) {
                if (ext->tcp.enable && !(ctx->hit = match_tcp(ctx->tcp, &ext->tcp))) return 0;
                if (ext->multi_port.src.enable && !(ctx->hit = match_multi_port(bpf_htons(ctx->tcp->source), &ext->multi_port.src))) return 0;
                if (ext->multi_port.dst.enable && !(ctx->hit = match_multi_port(bpf_htons(ctx->tcp->dest), &ext->multi_port.dst))) return 0;
            }
            break;
        default:
            // support empty rule
            break;
    }

    if (!within_limit(key)) {
        ctx->action = DROP;
        return 1;
    }

    if (ctx->hit) {
        ctx->action = rule->target;
        return 1;
    }

    return 0;
}

SEC("xdp/ingress/filter")
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
