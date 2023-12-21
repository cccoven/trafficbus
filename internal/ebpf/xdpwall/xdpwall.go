package xdpwall

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ipset_direction -type ipset_item -type rule_item -target amd64 bpf xdpwall.c -- -I../include

const MaxRules = 100

type XdpWall struct {
	ipsetMap map[int]*bpfIpsets
	ruleMap  map[int]*bpfRules

	objs  bpfObjects
	links map[int]link.Link
	sync.Mutex
}

func NewXdpWall() *XdpWall {
	x := &XdpWall{
		ipsetMap: make(map[int]*bpfIpsets),
		ruleMap:  make(map[int]*bpfRules),
		links:    make(map[int]link.Link),
	}

	x.loadObjects()

	return x
}

func (x *XdpWall) loadObjects() {
	// Load pre-compiled programs into the kernel.
	if err := loadBpfObjects(&x.objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
}

func (x *XdpWall) Stop() {
	x.objs.Close()
	for iface := range x.links {
		x.detach(iface)
	}
}

func (x *XdpWall) attach(iface int) {
	x.Lock()
	defer x.Unlock()

	var err error
	x.links[iface], err = link.AttachXDP(link.XDPOptions{
		Program:   x.objs.XdpWallFunc,
		Interface: iface,
	})
	if err != nil {
		log.Fatalf("could not attach xdp program: %s", err)
	}

	log.Printf("attached xdp program to iface index %d", iface)
}

func (x *XdpWall) detach(iface int) {
	x.Lock()
	defer x.Unlock()
	l, ok := x.links[iface]
	if !ok {
		return
	}
	l.Close()
	delete(x.links, iface)
	log.Printf("detached XDP program to iface %q", iface)
}

// InsertRule insert a rule into a specified position
func (x *XdpWall) InsertRule(iface string, pos int, rule Rule) error {
	if pos < 0 {
		return fmt.Errorf("invalid position %d", pos)
	}
	if pos > MaxRules {
		return fmt.Errorf("maximum number of rules exceeded: %d", MaxRules)
	}

	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	rules, ok := x.ruleMap[dev.Index]
	if !ok {
		rules = new(bpfRules)
		x.ruleMap[dev.Index] = rules
	}
	if pos > int(rules.Count) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	if pos == int(rules.Count) {
		// add to the end
		rules.Items[pos] = bpfRuleItem(rule)
	} else {
		// add to the `pos` position
		copy(rules.Items[pos+1:], rules.Items[pos:])
		rules.Items[pos] = bpfRuleItem(rule)
	}

	// update map
	err = x.objs.RuleMap.Update(uint32(dev.Index), rules, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	rules.Count++
	return nil
}

func (x *XdpWall) DeleteRule(iface string, pos int) error {

	return nil
}

func (x *XdpWall) Run() {
	for iface := range x.ruleMap {
		go x.attach(iface)
	}
}
