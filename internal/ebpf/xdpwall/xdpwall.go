package xdpwall

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ip_set_direction -type tcp_flag -type ip_item -type set_ext -type udp_ext -type tcp_ext -type tcp_flags -type multi_port_ext -type multi_port_pairs -type port_pair -type match_event -type target_ext -target amd64 Filter xdpwall.c -- -I../include

type IPSet [200]FilterIpItem

func (s *IPSet) EnabledSize() int {
	var size int
	for _, item := range s {
		if item.Enable == 0 {
			continue
		}
		size++
	}
	return size
}

type RuleMatchExtension struct {
	FilterMatchExt
	Limiter *FilterBucket
}

type Rule struct {
	FilterRule
	MatchExtension *RuleMatchExtension
}

// str2hash use uint32 hash as ipset name
func str2hash(s string) uint32 {
	if s == "" {
		return 0
	}
	hasher := fnv.New32()
	hasher.Write([]byte(s))
	return hasher.Sum32()
}

type Wall struct {
	objs  FilterObjects
	links map[int]link.Link
	sync.Mutex

	matchEventReader *ringbuf.Reader
	matchEvent       chan FilterMatchEvent
}

func NewWall() (*Wall, error) {
	x := &Wall{
		links:      make(map[int]link.Link),
		matchEvent: make(chan FilterMatchEvent),
	}

	err := LoadFilterObjects(&x.objs, nil)
	if err != nil {
		return nil, err
	}

	err = rlimit.RemoveMemlock()
	if err != nil {
		return nil, err
	}

	x.matchEventReader, err = ringbuf.NewReader(x.objs.MatchEvents)
	if err != nil {
		return nil, err
	}

	go x.listenMatchEvent()

	return x, nil
}

func (w *Wall) listenMatchEvent() {
	for {
		var evt FilterMatchEvent
		record, err := w.matchEventReader.Read()
		if err == ringbuf.ErrClosed {
			return
		}
		if err != nil {
			continue
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt)
		if err != nil {
			continue
		}

		w.matchEvent <- evt
	}
}

func (w *Wall) ReadMatchEvent() chan FilterMatchEvent {
	return w.matchEvent
}

func (w *Wall) Stop() error {
	for iface := range w.links {
		err := w.Detach(iface)
		if err != nil {
			return err
		}
	}
	w.matchEventReader.Close()
	close(w.matchEvent)

	w.objs.Close()
	return nil
}

func (w *Wall) Attach(iface int) error {
	w.Lock()
	defer w.Unlock()

	var err error
	w.links[iface], err = link.AttachXDP(link.XDPOptions{
		Program:   w.objs.XdpWallFunc,
		Interface: iface,
	})
	if err != nil {
		return err
	}

	return nil
}

func (w *Wall) Detach(iface int) error {
	w.Lock()
	defer w.Unlock()
	l, ok := w.links[iface]
	if !ok {
		return fmt.Errorf("link does not exist")
	}
	l.Close()
	delete(w.links, iface)
	log.Printf("detached xdp program to iface %q", iface)
	return nil
}

func (w *Wall) LookupSet(key uint32) (IPSet, error) {
	var set IPSet
	err := w.objs.IpSetMap.Lookup(key, &set)
	if err != nil {
		return set, err
	}

	return set, nil
}

func (w *Wall) CreateSet(key uint32) error {
	return w.objs.IpSetMap.Update(key, IPSet{}, ebpf.UpdateNoExist)
}

func (w *Wall) AppendIP(key uint32, ips ...FilterIpItem) error {
	set, err := w.LookupSet(key)
	if err != nil {
		return err
	}
	size := set.EnabledSize()

	for i, ip := range ips {
		set[i+size] = ip
	}

	return w.objs.IpSetMap.Update(key, set, ebpf.UpdateAny)
}

func (w *Wall) RemoveIP(key uint32, ip FilterIpItem) error {
	set, err := w.LookupSet(key)
	if err != nil {
		return err
	}

	for i, item := range set {
		if item.Addr == ip.Addr && item.Mask == ip.Mask {
			copy(set[i:], set[i+1:])
			break
		}
	}

	return w.objs.IpSetMap.Update(key, set, ebpf.UpdateAny)
}

func (w *Wall) ListRules() []*Rule {
	var key uint32
	var val FilterRule
	var rules []*Rule
	iter := w.objs.RuleMap.Iterate()
	for iter.Next(&key, &val) {
		if val.Enable == 1 {
			rule := &Rule{}
			rule.FilterRule = val

			var extension FilterMatchExt
			err := w.objs.MatchExtMap.Lookup(key, &extension)
			if err == nil {
				rule.MatchExtension = &RuleMatchExtension{}
				rule.MatchExtension.FilterMatchExt = extension

				var bucket FilterBucket
				err = w.objs.BucketMap.Lookup(key, &bucket)
				if err == nil {
					rule.MatchExtension.Limiter = &bucket
				}
			}
			rules = append(rules, rule)
		}
	}
	return rules
}

func (w *Wall) updateRule(key uint32, value *Rule) error {
	if err := w.objs.RuleMap.Update(key, value.FilterRule, ebpf.UpdateAny); err != nil {
		return err
	}
	extension := value.MatchExtension
	if extension != nil {
		if err := w.objs.MatchExtMap.Update(key, extension.FilterMatchExt, ebpf.UpdateAny); err != nil {
			return err
		}
		if extension.Limiter != nil {
			if err := w.objs.BucketMap.Update(key, extension.Limiter, ebpf.UpdateAny); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *Wall) batchUpdateRules(keys []uint32, values []*Rule) error {
	var (
		rules              []FilterRule
		matchExtensionKeys []uint32
		matchExtensionVals []FilterMatchExt
		bucketKeys         []uint32
		bucketVals         []FilterBucket
	)

	for i, r := range values {
		rules = append(rules, r.FilterRule)
		if r.MatchExtension != nil {
			matchExtensionKeys = append(matchExtensionKeys, keys[i])
			matchExtensionVals = append(matchExtensionVals, r.MatchExtension.FilterMatchExt)

			if r.MatchExtension.Limiter != nil {
				bucketKeys = append(bucketKeys, keys[i])
				bucketVals = append(bucketVals, *r.MatchExtension.Limiter)
			}
		}
	}
	_, err := w.objs.RuleMap.BatchUpdate(keys, rules, nil)
	if err != nil {
		return err
	}
	_, err = w.objs.MatchExtMap.BatchUpdate(matchExtensionKeys, matchExtensionVals, nil)
	if err != nil {
		return err
	}
	_, err = w.objs.BucketMap.BatchUpdate(bucketKeys, bucketVals, nil)
	if err != nil {
		return err
	}

	return nil
}

func (w *Wall) AppendRule(rules ...*Rule) error {
	size := len(w.ListRules())
	var keys []uint32
	var vals []*Rule
	for i, r := range rules {
		keys = append(keys, uint32(i+size))
		vals = append(vals, r)
	}
	return w.batchUpdateRules(keys, vals)
}

func (w *Wall) InsertRule(key int, rule *Rule) error {
	rules := w.ListRules()
	size := len(rules)

	err := w.updateRule(uint32(key), rule)
	if err != nil {
		return nil
	}

	if key < size {
		// delete elements first
		err = w.deleteRuleRange(key+1, size)
		if err != nil {
			return err
		}

		// move elements
		var keys []uint32
		var vals []*Rule
		for i, v := range rules[key:] {
			keys = append(keys, uint32(i+key+1))
			vals = append(vals, v)
		}
		err = w.batchUpdateRules(keys, vals)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *Wall) deleteRule(key uint32) error {
	// Since the array is of constant size, deletion operations is not supported.
	// To clear an array element, use Update to insert a zero value to that index.
	if err := w.objs.RuleMap.Update(key, &FilterRule{}, ebpf.UpdateAny); err != nil {
		return err
	}
	_ = w.objs.MatchExtMap.Delete(key)
	_ = w.objs.BucketMap.Delete(key)
	return nil
}

func (w *Wall) batchDeleteRules(keys []uint32) error {
	var values []FilterRule
	for range keys {
		values = append(values, FilterRule{})
	}
	_, err := w.objs.RuleMap.BatchUpdate(keys, values, nil)
	if err != nil {
		return err
	}
	_, _ = w.objs.MatchExtMap.BatchDelete(keys, nil)
	_, _ = w.objs.BucketMap.BatchDelete(keys, nil)
	return nil
}

func (w *Wall) DeleteRule(key int) error {
	rules := w.ListRules()
	size := len(rules)

	if key == size {
		err := w.deleteRule(uint32(key))
		if err != nil {
			return err
		}
	} else {
		err := w.deleteRuleRange(key, size)
		if err != nil {
			return err
		}

		var keys []uint32
		var vals []*Rule
		for i, v := range rules[key+1:] {
			keys = append(keys, uint32(i+key))
			vals = append(vals, v)
		}
		err = w.batchUpdateRules(keys, vals)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Wall) deleteRuleRange(start, end int) error {
	var keys []uint32
	for i := start; i < end; i++ {
		keys = append(keys, uint32(i))
	}
	return w.batchDeleteRules(keys)
}
