#pragma once

/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by libbpf depending on the context (BPF programs, BPF maps,
 * extern variables, etc).
 * To allow use of SEC() with externs (e.g., for extern .maps declarations),
 * make sure __attribute__((unused)) doesn't trigger compilation warning.
 */
#define SEC(name) \
    _Pragma("GCC diagnostic push")                      \
    _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")      \
    __attribute__((section(name), used))                    \
    _Pragma("GCC diagnostic pop")                       \

/* Avoid 'linux/stddef.h' definition of '__always_inline'. */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name


typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u16 __sum16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

/* packet */
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

#define ETH_ALEN    6		/* Octets in one ethernet addr	 */
#define ETH_TLEN	2		/* Octets in ethernet type field */

#define IPPROTO_ICMP    1               /* control message protocol */
#define IPPROTO_TCP     6               /* tcp */
#define IPPROTO_UDP     17              /* user datagram protocol */

struct ethhdr {
	unsigned char   h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char   h_source[ETH_ALEN];	/* source ether addr	*/
	__be16  h_proto;		/* packet type ID field	*/
};

struct iphdr {
    __u8    ihl: 4;
    __u8    version: 4;
    __u8    tos;
	__be16  tot_len;
	__be16  id;
	__be16  frag_off;
	__u8    ttl;
	__u8    protocol;
	__sum16 check;
    __be32  saddr;
    __be32  daddr;
};

struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

struct tcphdr {
    __be16  source;
	__be16  dest;
	__be32  seq;
	__be32	ack_seq;
    __u16   res1: 4;
    __u16   doff: 4;
    __u16   fin: 1;
    __u16   syn: 1;
    __u16   rst: 1;
    __u16   psh: 1;
    __u16   ack: 1;
    __u16   urg: 1;
    __u16   ece: 1;
    __u16   cwr: 1;
    __be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
