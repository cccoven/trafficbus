## iptables 执行流程图

```
                               XXXXXXXXXXXXXXXXXX
                             XXX     Network    XXX
                               XXXXXXXXXXXXXXXXXX
                                       +
                                       |
                                       v
 +-------------+              +------------------+
 |table: filter| <---+        | table: nat       |
 |chain: INPUT |     |        | chain: PREROUTING|
 +-----+-------+     |        +--------+---------+
       |             |                 |
       v             |                 v
 [local process]     |           ****************          +--------------+
       |             +---------+ Routing decision +------> |table: filter |
       v                         ****************          |chain: FORWARD|
****************                                           +------+-------+
Routing decision                                                  |
****************                                                  |
       |                                                          |
       v                        ****************                  |
+-------------+       +------>  Routing decision  <---------------+
|table: nat   |       |         ****************
|chain: OUTPUT|       |               +
+-----+-------+       |               |
      |               |               v
      v               |      +-------------------+
+--------------+      |      | table: nat        |
|table: filter | +----+      | chain: POSTROUTING|
|chain: OUTPUT |             +--------+----------+
+--------------+                      |
                                      v
                               XXXXXXXXXXXXXXXXXX
                             XXX    Network     XXX
                               XXXXXXXXXXXXXXXXXX
```

## iptables 规则

### NAT

```
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1    28871 5832K DOCKER     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL

Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1        3   180 DOCKER     all  --  *      *       0.0.0.0/0            !127.0.0.0/8          ADDRTYPE match dst-type LOCAL

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out                     source               destination         
1        0     0 MASQUERADE  all  --  *      !docker0               172.17.0.0/16        0.0.0.0/0           
2        1    84 MASQUERADE  all  --  *      !br-e48b41de8c32       172.18.0.0/16        0.0.0.0/0      // MASQUERADE 将源 IP 地址更改为宿主机的 IP 地址，以便这些数据包能够在外部网络中通信，类似于 SNAT --to-source 10.0.10.83     
3        0     0 MASQUERADE  tcp  --  *      *                      172.18.0.2           172.18.0.2           tcp dpt:6060
4        0     0 MASQUERADE  tcp  --  *      *                      172.18.0.3           172.18.0.3           tcp dpt:6379
5        0     0 MASQUERADE  udp  --  *      *                      172.18.0.2           172.18.0.2           udp dpt:5142

Chain DOCKER (2 references)
num   pkts bytes target     prot opt in                         out                  source               destination         
1        0     0 RETURN     all  --  docker0                    *                   0.0.0.0/0             0.0.0.0/0           
2        0     0 RETURN     all  --  br-e48b41de8c32            *                   0.0.0.0/0             0.0.0.0/0           
3        5   220 DNAT       tcp  --  !br-e48b41de8c32           *                   0.0.0.0/0             0.0.0.0/0            tcp dpt:6060 to:172.18.0.2:6060
4        2   120 DNAT       tcp  --  !br-e48b41de8c32           *                   0.0.0.0/0             0.0.0.0/0            tcp dpt:16379 to:172.18.0.3:6379
5     1307 2252K DNAT       udp  --  !br-e48b41de8c32           *                   0.0.0.0/0             0.0.0.0/0            udp dpt:5142 to:172.18.0.2:5142
```

### Filter

```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1     169K   14M ACCEPT     icmp --  *      *       123.456.789.251      0.0.0.0/0           
2    1797K  115M ACCEPT     tcp  --  *      *       123.456.789.251      0.0.0.0/0            multiport dports 10050,10051,39100
3    1535K  113M ACCEPT     all  --  *      *       123.456.789.128/25   0.0.0.0/0           
4    1789K 1220M ACCEPT     all  --  *      *       10.0.10.0/24         0.0.0.0/0           
5     6473 1972K ACCEPT     all  --  *      *       127.0.0.1            0.0.0.0/0           
6     6473 1972K DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target                     prot opt in                 out                 source               destination         
1    22730   41M DOCKER-USER                all  --  *                  *                   0.0.0.0/0            0.0.0.0/0           
2    22730   41M DOCKER-ISOLATION-STAGE-1   all  --  *                  *                   0.0.0.0/0            0.0.0.0/0           
3        0     0 ACCEPT                     all  --  *                  docker0             0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
4        0     0 DOCKER                     all  --  *                  docker0             0.0.0.0/0            0.0.0.0/0           
5        0     0 ACCEPT                     all  --  docker0            !docker0            0.0.0.0/0            0.0.0.0/0           
6        0     0 ACCEPT                     all  --  docker0            docker0             0.0.0.0/0            0.0.0.0/0           
7    36973   17M ACCEPT                     all  --  *                  br-e48b41de8c32     0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
8    3071K 5721M DOCKER                     all  --  *                  br-e48b41de8c32     0.0.0.0/0            0.0.0.0/0           
9     2292  190K ACCEPT                     all  --  br-e48b41de8c32    !br-e48b41de8c32    0.0.0.0/0            0.0.0.0/0           
10     115  6844 ACCEPT                     all  --  br-e48b41de8c32    br-e48b41de8c32     0.0.0.0/0            0.0.0.0/0           

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         

Chain DOCKER (2 references)
num   pkts bytes target     prot opt in                 out                 source               destination         
1        4   160 ACCEPT     tcp  --  !br-e48b41de8c32   br-e48b41de8c32     0.0.0.0/0            172.18.0.2           tcp dpt:6060
2        0     0 ACCEPT     tcp  --  !br-e48b41de8c32   br-e48b41de8c32     0.0.0.0/0            172.18.0.3           tcp dpt:6379
3    21459   39M ACCEPT     udp  --  !br-e48b41de8c32   br-e48b41de8c32     0.0.0.0/0            172.18.0.2           udp dpt:5142

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
num   pkts bytes target                     prot opt in                 out                     source               destination         
1        0     0 DOCKER-ISOLATION-STAGE-2   all  --  docker0            !docker0                0.0.0.0/0            0.0.0.0/0           
2        4   160 DOCKER-ISOLATION-STAGE-2   all  --  br-e48b41de8c32    !br-e48b41de8c32        0.0.0.0/0            0.0.0.0/0           
3    22730   41M RETURN                     all  --  *                  *                       0.0.0.0/0            0.0.0.0/0           

Chain DOCKER-ISOLATION-STAGE-2 (2 references)
num   pkts bytes target     prot opt in     out                 source               destination         
1        0     0 DROP       all  --  *      docker0             0.0.0.0/0            0.0.0.0/0           
2        0     0 DROP       all  --  *      br-e48b41de8c32     0.0.0.0/0            0.0.0.0/0           
3        4   160 RETURN     all  --  *      *                   0.0.0.0/0            0.0.0.0/0           

Chain DOCKER-USER (1 references)
num   pkts bytes target     prot opt in     out     source               destination         
1    3110K 5739M RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0 
```


## 系统路由表

```
default via 124.232.163.129 dev eno1 
10.0.10.0/24 dev eno1 proto kernel scope link src 10.0.10.83 
123.456.789.128/25 dev eno1 proto kernel scope link src 123.456.789.208 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
172.18.0.0/16 dev br-e48b41de8c32 proto kernel scope link src 172.18.0.1
```

## 问题

在 `INPUT` 规则 `DROP ALL` 规则前已经存在 `10.0.10.0/24` 段放行的规则，但使用 `nc -z -v -w2 10.0.10.83 16379` 命令连接 docker 中运行的 redis 时仍然无法连接。

由于还有一条 `127.0.0.1` 放行规则的存在，使用 `nc -z -v -w2 127.0.0.1 16379` 可以正常连接，但实际上进程内也无法实际连接到 redis，考虑到可能是因为**环回网卡的数据包（localhost）不会进入 NAT 表处理**的原因。

## 执行流程

假设以下命令：

```
nc -z -v -w2 10.0.10.83 16379
```

这条命令的完整执行流程如下：

1. 最初的数据包为 `10.0.10.83:xxx -> 10.0.10.83:16379`，根据路由表，这条数据包处于 `10.0.10.0/24`，进入 `eno1` 网卡。

2. 该数据包进入 iptables，首先经过 `NAT PREROUTING` 链将目标地址转换为 `172.18.0.3:6379`，此时数据包为 `10.0.10.83:xxx -> 172.18.0.3:6379`。

3. 系统进行 `Routing decision`，查找路由表，由于本条数据包目的地址已经被转成 `172.18.0.0` 段，根据路由表规则得知这条数据需要走 `br-e48b41de8c32` 网卡，最终 `Routing decision` 判定为*转发*，根据流程图，进入 `filter FORWARD` 链（注意：即使 iptables 中没有任何规则，系统也会根据路由表中的指示将数据包进行转发到对应的网卡）。`filter FORWARD` 链处理完之后该数据包正常转发到 `br-e48b41de8c32` 网卡，该数据包的流程结束。

4. `br-e48b41de8c32` 网卡收到转发的数据包，同样先进入`NAT PREROUTING` 链，该数据包的 `in` 网卡为 `br-e48b41de8c32`，没有匹配到任何规则，然后系统进行 `Routing decision`，系统发现本条数据包目的地址是 `172.18.0.0` 段且是由 `br-e48b41de8c32` 网卡进入的，最终判定为*正常*，进入 `filter INPUT` 链。

5. `filter INPUT` 链中匹配到源 IP 属于 `10.0.10.0/24` 段，执行放行操作，然后进行 `NAT OUTPUT`、`filter OUTPUT`、`NAT POSTROUTING` 的匹配，最终成功将数据包发送给 `172.18.0.3:6379`。（之前这里我以为这条数据进入 `filter INPUT` 链之后就被后面的 `DROP all` 丢弃了，其实不是的，这条数据实际已经能够成功发送出去了，真正被丢弃的是 `172.18.0.3:6379` 的回包，由于 `INPUT` 中没有 `172.18.0.0` 段的放行规则，导致相关的回包会被丢弃）。

6. 现在假设已经添加了 `172.18.0.0` 段的放行规则，`172.18.0.3:6379` 的回包为 `172.18.0.3:6379 -> 10.0.10.83:xxx`，根据路由表，这条数据包处于 `10.0.10.0/24`，进入 `eno1` 网卡。

7. 回包也会进入 iptables，经过相同的规则检测，最后在 `NAT POSTROUTING` 链中将源 IP 转为本机的 `IP`（如 `10.0.10.83`）与外部网络通信。

## 问题原因

根据执行流程最终得出结论：docker 在 NAT 中进行了目标地址转换，导致容器的回包被 `DROP all` 丢弃。可以添加容器段 `172.18.0.0` 的放行规则解决问题，如果主机上运行了多个容器网络，可以权衡考虑 `DROP all` 和配置规则的使用。

<!-- 由于 nc 127.0.0.1 并没有实际 -->
