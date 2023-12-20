package xdpwall

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ipset_direction -target amd64 bpf xdpwall.c -- -I../include

type XdpWall struct {
	ipSets map[string][]IPSetKV
	rules  map[string][]Rule

	objs  bpfObjects
	links map[string]link.Link
	sync.Mutex
}

func NewXdpWall() *XdpWall {
	x := &XdpWall{
		ipSets: make(map[string][]IPSetKV),
		rules:  make(map[string][]Rule),
		links:  make(map[string]link.Link),
	}

	x.loadObjects()

	return x
}

func (x *XdpWall) loadIPSet(outerMap *ebpf.Map, innerMap *ebpf.Map) error {
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

func (x *XdpWall) loadRules(emap *ebpf.Map) error {
	// keys := make([]uint32, len(x.rules))
	// values := make([]bpfXdpRule, len(x.rules))
	// // load rule map
	// for i, rule := range x.rules {
	// 	keys[i] = uint32(rule.Num)
	// 	values[i] = rule
	// }

	// _, err := emap.BatchUpdate(keys, values, nil)
	// if err != nil {
	// 	return err
	// }

	return nil
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

func (x *XdpWall) attach(iface string) {
	x.Lock()
	defer x.Unlock()
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", iface, err)
	}

	x.links[iface], err = link.AttachXDP(link.XDPOptions{
		Program:   x.objs.XdpProdFunc,
		Interface: ifc.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}

	log.Printf("Attached XDP program to iface %q (index %d)", ifc.Name, ifc.Index)
}

func (x *XdpWall) detach(iface string) {
	x.Lock()
	defer x.Unlock()
	l, ok := x.links[iface]
	if !ok {
		return
	}
	l.Close()
	delete(x.links, iface)
	log.Printf("Detached XDP program to iface %q", iface)
}

func (x *XdpWall) getRuleKvs(iface string, pos int) ([]uint32, []Rule) {
	keys := []uint32{}
	for i := pos; i < len(x.rules[iface]); i++ {
		keys = append(keys, uint32(i))
	}
	return keys, x.rules[iface][pos:]
}

// InsertRule insert a rule into a specified position
func (x *XdpWall) InsertRule(iface string, pos int, rule Rule) error {
	if pos < 0 {
		return fmt.Errorf("invalid position %d", pos)
	}
	rules, ok := x.rules[iface]
	if pos > len(rules) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	if !ok || pos == len(rules) {
		// add to the end
		x.rules[iface] = append(x.rules[iface], rule)
	} else {
		// add to the `pos` position
		x.rules[iface] = append(x.rules[iface], Rule{})
		copy(x.rules[iface][pos+1:], x.rules[iface][pos:])
		x.rules[iface][pos] = rule
	}

	// batch update map.
	// only the rules that need to be changed are updated here
	keys, values := x.getRuleKvs(iface, pos)
	return x.updateRules(iface, keys, values)
}

// updateRules batch update the rule map.
// keys and values must correspond one to one
func (x *XdpWall) updateRules(iface string, keys []uint32, rules []Rule) error {
	if len(keys) != len(rules) {
		return fmt.Errorf("the length of keys and values are different")
	}

	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	// innerMap, err := x.objs.RuleInnerMap.Clone()
	// if err != nil {
	// 	return err
	// }

	// _, err = innerMap.BatchUpdate(keys, rules, nil)
	// if err != nil {
	// 	return err
	// }
	// err = x.objs.RuleMap.Update(uint32(dev.Index), innerMap, ebpf.UpdateAny)
	// if err != nil {
	// 	return err
	// }

	innerMapSpec := &ebpf.MapSpec{
		Name:    "rule_inner_map",
		Type:    ebpf.Array,
		KeySize: 4,
		Value:   &btf.Void{},
		// ValueSize:  uint32(unsafe.Sizeof(rules[0])),
		MaxEntries: 1,
		Flags:      0x1000,
	}
	innerMapSpec.Contents = make([]ebpf.MapKV, 1)
	for i := range innerMapSpec.Contents {
		innerMapSpec.Contents[uint32(i)] = ebpf.MapKV{Key: uint32(i), Value: rules[0]}
	}
	innerMap, err := ebpf.NewMap(innerMapSpec)
	if err != nil {
		return err
	}
	err = x.objs.RuleMap.Update(uint32(dev.Index), innerMap, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	// _, err = x.objs.RuleInnerMap.BatchUpdate(keys, rules, nil)
	// if err != nil {
	// 	return err
	// }
	// err = x.objs.RuleMap.Update(uint32(dev.Index), x.objs.RuleInnerMap, ebpf.UpdateAny)
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (x *XdpWall) DeleteRule(iface string, pos int) error {
	// if pos < 0 {
	// 	return fmt.Errorf("invalid position %d", pos)
	// }
	// rules, ok := x.rules[iface]
	// if pos > len(rules) {
	// 	return fmt.Errorf("position %d is out of range", pos)
	// }

	return nil
}

func (x *XdpWall) DeleteRuleMap(iface string, key uint32) error {
	return x.objs.RuleMap.Delete(key)
}

func (x *XdpWall) Run() {
	for iface := range x.rules {
		go x.attach(iface)
	}
}
