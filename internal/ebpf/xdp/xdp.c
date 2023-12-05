//go:build ignore

#include "bpf_helper.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_RULES 2

enum protocol {
    ICMP = IPPROTO_ICMP,
    UDP = IPPROTO_UDP,
    TCP = IPPROTO_TCP,
};

// common rule
struct xdp_rule {
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

// Force emitting enum xdp_action into the ELF.
const enum xdp_action *action __attribute__((unused));
const enum protocol *prot __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct xdp_rule);
} xdp_rule_map SEC(".maps");

struct callback_ctx {
    struct xdp_md *xdp_data;
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

static __u32 __always_inline match_tcp(const struct tcphdr *tcp, const struct xdp_rule *rule) {
    __bpf_printk("data_offset: %d, rule_ip: %d, pkt_ip: %d\n", tcp->doff, rule->source, tcp->source);
    return XDP_PASS;
}

static __u64 callback_fn(void *map, __u32 *key, struct xdp_rule *value, struct callback_ctx *ctx) {
    void *data = (void *)(long)ctx->xdp_data->data;
    void *data_end = (void *)(long)ctx->xdp_data->data_end;
    struct cursor cur = { .pos = data };

    struct ethhdr *eth;
    if (!parse_ethhdr(&cur, data_end, &eth)) {
        return 1;
    }

    // make sure it's IPv4
    if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        return 1;
    }

    struct iphdr *ip;
    if (!parse_iphdr(&cur, data_end, &ip)) {
        return 1;
    }

    if (value->protocol == IPPROTO_ICMP) {
        // TODO
        ctx->action = XDP_PASS;
        return 1;
    }

    if (value->protocol == IPPROTO_UDP) {
        // TODO
        ctx->action = XDP_PASS;
        return 1;
    }

    if (value->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        if (!parse_tcphdr(&cur, data_end, &tcp)) {
            return 1;
        }
        match_tcp(tcp, value);
    }
    
    return 0;
}

SEC("xdp")
int xdp_prod_func(struct xdp_md *ctx) {
    struct callback_ctx cb_ctx = {
        .xdp_data = ctx,
        .action = XDP_PASS,
    };
    bpf_for_each_map_elem(&xdp_rule_map, callback_fn, &cb_ctx, BPF_ANY);
done:
    return cb_ctx.action;
}
