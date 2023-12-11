package xdp

import (
	"log"
	"net"
	"time"

	"github.com/cccoven/trafficbus"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -target amd64 bpf xdp.c -- -I../include

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

func (x *Xdp) loadRules(objs *bpfObjects) error {
	keys := make([]uint32, len(x.rules))
	values := make([]bpfXdpRule, len(x.rules))
	// load rule map
	for i, rule := range x.rules {
		keys[i] = uint32(rule.Num)
		values[i] = rule
	}

	_, err := objs.XdpRuleMap.BatchUpdate(keys, values, nil)
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

	err = x.loadRules(&objs)
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
