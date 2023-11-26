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

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
