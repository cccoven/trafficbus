package xdp

import (
	"log"
	"net"
	"time"

	"github.com/cccoven/trafficbus"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type xdp_action -type protocol -target amd64 bpf xdp.c -- -I../include

type XDP struct {
	iface string
	rules []bpfXdpRule
}

func NewXDP(iface string, rules []bpfXdpRule) trafficbus.Adapter {
	return &XDP{
		iface: iface,
		rules: rules,
	}
}

func (x *XDP) Run() {
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

	// load rule map
	for _, rule := range x.rules {
		objs.XdpRuleMap.Put(rule.Num, &rule)
	}

	for {
		time.Sleep(time.Second)
	}
}
