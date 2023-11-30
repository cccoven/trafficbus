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
}

func NewXDP(iface string) trafficbus.Adapter {
	return &XDP{
		iface: iface,
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

	rule := bpfXdpRule{
		Num:             1,
		Pkts:            0,
		Bytes:           0,
		Target:          uint32(bpfXdpActionXDP_PASS),
		Protocol:        uint32(bpfProtocolTCP),
		Source:          uint32(100),
		SourceMask:      uint32(100),
		Destination:     uint32(100),
		DestinationMask: uint32(100),
	}
	rule2 := bpfXdpRule{
		Num:             2,
		Pkts:            0,
		Bytes:           0,
		Target:          uint32(bpfXdpActionXDP_DROP),
		Protocol:        uint32(bpfProtocolTCP),
		Source:          uint32(200),
		SourceMask:      uint32(200),
		Destination:     uint32(200),
		DestinationMask: uint32(200),
	}

	objs.XdpRuleMap.Put(uint32(0), &rule)
	objs.XdpRuleMap.Put(uint32(1), &rule2)

	for {
		time.Sleep(time.Second)
	}
}
