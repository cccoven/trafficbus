#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

/**
 * 在 CIDR（Classless Inter-Domain Routing，无类域间路由）表示法中，子网掩码的位数表示了网络部分的长度。
 * 如 192.168.1.0/24 中的 /24 表示网络地址占用 24 位，剩下的 8 位用于主机地址。这里的 8 位共有 2 的 8 次方个可能的组合，即有 256 个可能的主机地址。
 * 
 * 192.168.1.0/24 => /24 => (32-24) => 8
 * 一个 ipv4 地址有 32 位，每个 . 表示 8 位，总共 4 个字节（uint32）
 * 24 表示网络地址，即 192.168.1，剩下的 8 位表示主机数，表明在 192.168.1 网络地址下有 2^(32-24)=256 个主机数量，即 2的8次方 = 2*2*2*2*2*2*2*2 = 256
 * 
 * 在二进制中，每一位的最大值是 1，八位二进制数的最大值是 11111111（二进制）或者 0xff（十六进制）。这八位二进制数的最大值对应的十进制数就是 255
 * 11111111 或 0xff 在十进制下都表示 255。
 * 
 * 使用左移操作符 (<<) 运算掩码，<< 将第一个操作数向左移动指定位数，左边超出的位数将会被清除，右边将会补零
 * 最终结果为
 * 11111111.11111111.11111111.11111111 << 8 = 11111111.11111111.11111111.00000000
 * 0xffffffff << 8 = 0xffffff00
 * 255.255.255.255 << 8 = 255.255.255. 0
 * 
*/

char *getNet(const char *net_addr) {
    const char ch = '/';
    char *token;
    token = strchr(net_addr, ch);
    if (token) {
        char *net = malloc(token - net_addr + 1);
        if (net) {
            strncpy(net, net_addr, token - net_addr);
            net[token - net_addr] = '\0';
            return net;
        }
    }
    return NULL;
}

int getPrefix(const char *net_addr) {
    const char ch = '/';
    char *ret;
    ret = strchr(net_addr, ch);
    if (ret) {
        return atoi(ret + 1);
    }
    return -1;
}

// isSubnet 函数判断一个 IP 是否在位于一个网段内
int isSubnet(const char *net_addr, const char *ip_addr) {
    // 192.168.1.0
    char *net = getNet(net_addr);
    // 24
    int prefix = getPrefix(net_addr);
    
    // 获取子网掩码，如 255.255.255.0
    char mask_ip[INET_ADDRSTRLEN];
    uint32_t bits = 0xffffffff << (32 - prefix); // 这个 bits 不能直接用来与运算，因为它是完整的位，如 ffffff00，而 mask 是 ffffff
    printf("bits: %x\n", bits);
    struct in_addr addr;
    addr.s_addr = htonl(bits);
    strcpy(mask_ip, inet_ntoa(addr));

    // in_addr_t = uint32_t
    in_addr_t mask = inet_addr(mask_ip); // 11111111.11111111.11111111 这里只有网段部分，即 192.168.1
    in_addr_t network = inet_addr(net);  // 11010100011000000
    in_addr_t ia = inet_addr(ip_addr);   // 1000000011010100011000000

    printf("mask: %x\n", mask);
    printf("network: %x\n", network);
    printf("ip: %x\n", ia);


    // 进行对比时，长度不够的位会补 0，这里要去掉尾部的主机名，即小端法的前 8 位，因为只需要对比网段部分
    // 192.168.1.0 & 255.255.255.0
    // 00000000.00000011.01010001.10000000
    // 00000000.11111111.11111111.11111111
    // =
    // 00000000.00000011.01010001.10000000
    uint32_t a = (network & mask);

    // 192.168.1.1 & 255.255.255.0
    // 00000010.00000011.01010001.10000000
    // 00000000.11111111.11111111.11111111
    // = 
    // 00000000.00000011.01010001.10000000 
    // 
    // 假设 ip 段是 192.168.10.1，那么 192.168.10.1 & 255.255.255.0 的结果就是，最终与网段部分不相等
    // 00000000.00001010.10101000.11000000
    // 00000000.11111111.11111111.11111111
    // =
    // 00000000.00001010.10101000.11000000
    uint32_t b = (ia & mask);

    printf("network & mask: %x\n", a);
    printf("ip & mask: %x\n", b);

    return a == b;
}


void subnetMaskFromPrefix(int prefixLength, char* mask) {
    uint32_t bits = 0xffffffff << (32 - prefixLength);
    printf("bits: %x\n", bits);
    struct in_addr addr;
    addr.s_addr = htonl(bits);
    strcpy(mask, inet_ntoa(addr));
}

int isSubnet2(const char *net_addr, const char *ip_addr) {
    char *net = getNet(net_addr); // 192.168.1.0
    int netbit = getPrefix(net_addr); // 24

    uint32_t prefix = (32 - netbit);
    uint32_t bits = 0xffffffff << prefix;
    uint32_t maskip = ntohl(bits);
    uint32_t netip = inet_addr(net);
    uint32_t ip = inet_addr(ip_addr);
    printf("maskip: %x, netip: %x, ip: %x\n", maskip, netip, ip);

    uint32_t a = netip & maskip;
    uint32_t b = ip & maskip;
    printf("a: %x, b: %x\n", a, b);

    return a == b;
}

int isSubnet3(uint32_t netip, uint32_t mask, uint32_t ip) {
    uint32_t prefix = (32 - mask);
    uint32_t bits = (0xffffffff << prefix);
    printf("bits: %x\n", bits);

    // uint32_t maskip = htonl(bits);
    // printf("maskip: %x, netip: %x, ip: %x\n", maskip, netip >> prefix, ip >> prefix);
    // printf("maskip: %u, netip: %u, ip: %u\n", maskip, netip >> prefix, ip >> prefix);

    // uint32_t a = (netip >> prefix) & maskip;
    // uint32_t b = (ip >> prefix) & maskip;
    // printf("a: %x, b: %x\n", a, b);

    uint32_t maskip = htonl(bits) << prefix;
    printf("maskip: %x, netip: %x, ip: %x\n", maskip, netip, ip);
    printf("maskip: %u, netip: %u, ip: %u\n", maskip, netip, ip);

    uint32_t a = netip & maskip;
    uint32_t b = ip & maskip;
    printf("a: %x, b: %x\n", a, b);

    return a == b;
}

int isSubnet4(const char *net_addr, const char *ip_addr) {
    char *net = getNet(net_addr); // 192.168.1.0
    int netbit = getPrefix(net_addr); // 24

    struct in_addr netaddr;
    inet_pton(AF_INET, net, &netaddr);
    uint32_t netip = htonl(netaddr.s_addr);

    struct in_addr ipaddr;
    inet_pton(AF_INET, ip_addr, &ipaddr);
    uint32_t ip = htonl(ipaddr.s_addr);

    return isSubnet3(netip, netbit, ip);
}


int main() {
    char *net_addr = "192.168.1.0/24";
    const char *ip_addr = "192.168.1.100";
    int rv = isSubnet4(net_addr, ip_addr);
    printf("isSubnet: %u\n", rv);
    return 0;
}