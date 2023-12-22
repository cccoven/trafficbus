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

func (x *XdpWall) Stop() error {
	for iface := range x.links {
		err := x.detach(iface)
		if err != nil {
			return err
		}
	}
	return x.objs.Close()
}

func (x *XdpWall) Attach(iface string) error {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	return x.attach(dev.Index)
}

func (x *XdpWall) attach(iface int) error {
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
	return nil
}

func (x *XdpWall) Detach(iface string) error {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	return x.detach(dev.Index)
}

func (x *XdpWall) detach(iface int) error {
	x.Lock()
	defer x.Unlock()
	l, ok := x.links[iface]
	if !ok {
		return fmt.Errorf("link does not exists")
	}
	l.Close()
	delete(x.links, iface)
	log.Printf("detached xdp program to iface %q", iface)
	return nil
}

func (x *XdpWall) insertRule(iface int, pos int, rule Rule) error {
	rules, ok := x.ruleMap[iface]
	if !ok {
		rules = new(bpfRules)
		x.ruleMap[iface] = rules
	}
	if pos > int(rules.Count) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	if pos != int(rules.Count) {
		// move elements behind `pos`
		copy(rules.Items[pos+1:], rules.Items[pos:])
	}
	rules.Items[pos] = bpfRuleItem(rule)
	rules.Count++

	// update map
	err := x.objs.RuleMap.Update(uint32(iface), rules, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
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

	return x.insertRule(dev.Index, pos, rule)
}

func (x *XdpWall) AppendRule(iface string, rule Rule) error {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	pos := 0
	rules, ok := x.ruleMap[dev.Index]
	if ok {
		pos = int(rules.Count)
	}

	return x.insertRule(dev.Index, pos, rule)
}

func (x *XdpWall) DeleteRule(iface string, pos int) error {
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
		return fmt.Errorf("rules for iface %s does not exists", iface)
	}
	if pos > int(rules.Count) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	rules.Items[pos] = bpfRuleItem{}
	rules.Count--
	if pos != int(rules.Count) {
		copy(rules.Items[pos:], rules.Items[pos+1:])
	}

	err = x.objs.RuleMap.Update(uint32(dev.Index), rules, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func (x *XdpWall) Run() error {
	for iface := range x.ruleMap {
		err := x.attach(iface)
		if err != nil {
			return err
		}
	}
	return nil
}
