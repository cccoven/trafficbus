package xdpwall

import (
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"sync"

	"github.com/cccoven/trafficbus/internal"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ip_set_direction -type ip_item -type rule_item -type match_ext -type set_ext -type udp_ext -type tcp_ext -type target_ext -target amd64 Filter xdpwall.c -- -I../include

const MaxRules = 100

type XdpWall struct {
	objs  FilterObjects
	links map[int]link.Link
	sync.Mutex
}

func NewXdpWall() *XdpWall {
	x := &XdpWall{
		links: make(map[int]link.Link),
	}

	x.loadObjects()

	return x
}

func (x *XdpWall) loadObjects() {
	// Load pre-compiled programs into the kernel.
	if err := LoadFilterObjects(&x.objs, nil); err != nil {
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
		return fmt.Errorf("link does not exist")
	}
	l.Close()
	delete(x.links, iface)
	log.Printf("detached xdp program to iface %q", iface)
	return nil
}

// GenIpSetID use uint32 hash as ipset name
func (w *XdpWall) GenIpSetID(s string) uint32 {
	hasher := fnv.New32()
	hasher.Write([]byte(s))
	return hasher.Sum32()
}

func (x *XdpWall) LookupIpSet(setName string) (*FilterIpSet, error) {
	ipSet := &FilterIpSet{}
	err := x.objs.IpSetMap.Lookup(x.GenIpSetID(setName), ipSet)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("ip set `%s` does not exist", setName)
		}
		return nil, err
	}
	return ipSet, nil
}

func (x *XdpWall) CreateIpSet(setName string) error {
	err := x.objs.IpSetMap.Update(x.GenIpSetID(setName), &FilterIpSet{}, ebpf.UpdateNoExist)
	if errors.Is(err, ebpf.ErrKeyExist) {
		return fmt.Errorf("ip set `%s` already exists", setName)
	}
	return err
}

func (x *XdpWall) AppendIp(setName string, ips ...string) error {
	ipSet, err := x.LookupIpSet(setName)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		uip, umask, err := internal.ParseV4CIDRU32(ip)
		if err != nil {
			return err
		}
		ipSet.Items[ipSet.Count] = FilterIpItem{
			Addr: uip,
			Mask: umask,
		}
		ipSet.Count++
	}

	return x.objs.IpSetMap.Update(x.GenIpSetID(setName), ipSet, ebpf.UpdateAny)
}

func (x *XdpWall) DelIpSet(setName string) error {
	return x.objs.IpSetMap.Delete(x.GenIpSetID(setName))
}

func (x *XdpWall) RemoveIp(setName, ip string) error {
	ipSet, err := x.LookupIpSet(setName)
	if err != nil {
		return err
	}

	uip, umask, err := internal.ParseV4CIDRU32(ip)
	if err != nil {
		return err
	}

	found := false
	pos := 0
	for ; pos < int(ipSet.Count); pos++ {
		item := ipSet.Items[pos]
		if item.Addr == uip && item.Mask == umask {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("no such ip %s", ip)
	}

	ipSet.Items[pos] = FilterIpItem{}
	ipSet.Count--
	if pos != int(ipSet.Count) {
		copy(ipSet.Items[pos:], ipSet.Items[pos+1:])
	}

	return x.objs.IpSetMap.Update(x.GenIpSetID(setName), ipSet, ebpf.UpdateAny)
}

func (x *XdpWall) LookupRuleSet(iface string) (*FilterRuleSet, error) {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	rules := &FilterRuleSet{}
	err = x.objs.RuleSetMap.Lookup(uint32(dev.Index), rules)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("rule set `%s` does not exist", iface)
		}
		return nil, err
	}
	return rules, nil
}

func (x *XdpWall) CreateRuleSet(iface string) error {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	err = x.objs.RuleSetMap.Update(uint32(dev.Index), &FilterRuleSet{}, ebpf.UpdateNoExist)
	if errors.Is(err, ebpf.ErrKeyExist) {
		return fmt.Errorf("rule set `%s` already exists", iface)
	}
	return err
}

// InsertRule insert a rule into a specified position
func (x *XdpWall) InsertRule(iface string, pos int, rule FilterRuleItem) error {
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

	ruleSet, err := x.LookupRuleSet(iface)
	if err != nil {
		return err
	}

	if pos > int(ruleSet.Count) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	if pos != int(ruleSet.Count) {
		// move elements behind `pos`
		copy(ruleSet.Items[pos+1:], ruleSet.Items[pos:])
	}
	ruleSet.Items[pos] = rule
	ruleSet.Count++

	// update map
	err = x.objs.RuleSetMap.Update(uint32(dev.Index), ruleSet, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func (x *XdpWall) AppendRule(iface string, rules ...FilterRuleItem) error {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	ruleSet, err := x.LookupRuleSet(iface)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		ruleSet.Items[ruleSet.Count] = rule
		ruleSet.Count++
	}

	return x.objs.RuleSetMap.Update(uint32(dev.Index), ruleSet, ebpf.UpdateAny)
}

func (x *XdpWall) RemoveRule(iface string, pos int) error {
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

	ruleSet, err := x.LookupRuleSet(iface)
	if err != nil {
		return err
	}
	if pos > int(ruleSet.Count) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	ruleSet.Items[pos] = FilterRuleItem{}
	ruleSet.Count--
	if pos != int(ruleSet.Count) {
		copy(ruleSet.Items[pos:], ruleSet.Items[pos+1:])
	}

	err = x.objs.RuleSetMap.Update(uint32(dev.Index), ruleSet, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func (x *XdpWall) DelRuleSet(iface string) error {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	return x.objs.RuleSetMap.Delete(uint32(dev.Index))
}
