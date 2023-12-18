package xdp

import (
	"log"
	"net"
	"time"

	"github.com/cccoven/trafficbus"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ipset_type -target amd64 bpf xdp.c -- -I../include

type Xdp struct {
	iface string
	rules []bpfXdpRule
}

func NewXdp(iface string, rules []bpfXdpRule) trafficbus.Adapter {
	return &Xdp{
		iface: iface,
		rules: rules,
	}
}

func str2uint(d []uint8, s string) {
	for i, char := range s {
		if i >= len(d) {
			break
		}
		d[i] = uint8(char)
	}
}

func (x *Xdp) loadIPSet(outerMap *ebpf.Map, innerMap *ebpf.Map) error {
	innerKey := bpfIpv4LpmKey{
		Prefixlen: uint32(32),
		Data:      uint32(2130706433),
	}
	innerVal := bpfIpv4LpmVal{
		Addr: 1234,
		Mask: 5678,
	}
	err := innerMap.Put(&innerKey, &innerVal)
	if err != nil {
		return err
	}

	// outerKey := bpfIpsetKey{}
	// str2uint(outerKey.Name[:], "myset")

	err = outerMap.Put(uint32(1234), innerMap)
	if err != nil {
		return err
	}

	// k := &bpfIpsetKey{}
	// str2uint(k.Name[:], "myset")

	// v := &bpfIpsetVal{}
	// v.Addrs[0] = 2130706433
	// v.Masks[0] = 2130706433

	// v.NumEntry++

	// err := emap.Put(k, v)
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (x *Xdp) loadRules(emap *ebpf.Map) error {
	keys := make([]uint32, len(x.rules))
	values := make([]bpfXdpRule, len(x.rules))
	// load rule map
	for i, rule := range x.rules {
		keys[i] = uint32(rule.Num)
		values[i] = rule
	}

	_, err := emap.BatchUpdate(keys, values, nil)
	if err != nil {
		return err
	}

	return nil
}

func (x *Xdp) Run() {
	iface, err := net.InterfaceByName(x.iface)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", x.iface, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	err = x.loadIPSet(objs.IpsetMap, objs.IpsetInnerMap)
	if err != nil {
		log.Fatalf("failed to load ipset to map: %s", err.Error())
	}

	err = x.loadRules(objs.RuleMap)
	if err != nil {
		log.Fatalf("failed to load rules to map: %s", err.Error())
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProdFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	for {
		time.Sleep(time.Second)
	}
}
