package xdpwall

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

type XdpWall struct {
	objs       FilterObjects
	links      map[int]link.Link
	rbufReader *ringbuf.Reader
	sync.Mutex

	matchEventReader *ringbuf.Reader
	matchEvent       chan FilterMatchEvent
}

func NewXdpWall() (*XdpWall, error) {
	x := &XdpWall{
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

func (x *XdpWall) listenMatchEvent() {
	for {
		var evt FilterMatchEvent
		record, err := x.matchEventReader.Read()
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

		x.matchEvent <- evt
	}
}

func (x *XdpWall) ReadMatchEvent() chan FilterMatchEvent {
	return x.matchEvent
}

func (x *XdpWall) Stop() error {
	for iface := range x.links {
		err := x.Detach(iface)
		if err != nil {
			return err
		}
	}
	x.matchEventReader.Close()
	close(x.matchEvent)

	x.objs.Close()
	return nil
}

func (x *XdpWall) Attach(iface int) error {
	x.Lock()
	defer x.Unlock()

	var err error
	x.links[iface], err = link.AttachXDP(link.XDPOptions{
		Program:   x.objs.XdpWallFunc,
		Interface: iface,
	})
	if err != nil {
		return err
	}

	return nil
}

func (x *XdpWall) Detach(iface int) error {
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

func (x *XdpWall) LookupIPSet(key uint32) (IPSet, error) {
	var set IPSet
	err := x.objs.IpSetMap.Lookup(key, &set)
	if err != nil {
		return set, err
	}

	return set, nil
}

func (x *XdpWall) UpdateIPSet(key uint32, val IPSet) error {
	return x.objs.IpSetMap.Update(key, val, ebpf.UpdateAny)
}

func (x *XdpWall) ListRules() []FilterRule {
	var key uint32
	var val FilterRule
	var rules []FilterRule

	iter := x.objs.RuleMap.Iterate()
	for iter.Next(&key, &val) {
		if val.Enable == 1 {
			rules = append(rules, val)
		}
	}

	return rules
}

// UpdateRule updates a rule.
// Since the array is of constant size, deletion operations is not supported.
// To clear an array element, use Update to insert a zero value to that index.
func (x *XdpWall) UpdateRule(key uint32, value *FilterRule) error {
	if value == nil {
		value = &FilterRule{}
	}
	return x.objs.RuleMap.Update(key, value, ebpf.UpdateAny)
}

func (x *XdpWall) UpdateRules(keys []uint32, values []FilterRule) (int, error) {
	return x.objs.RuleMap.BatchUpdate(keys, values, nil)
}

func (x *XdpWall) UpdateMatchExt(key uint32, value *FilterMatchExt) error {
	return x.objs.MatchExtMap.Update(key, value, ebpf.UpdateAny)
}

func (x *XdpWall) UpdateMatchExts(keys []uint32, values []FilterMatchExt) (int, error) {
	return x.objs.MatchExtMap.BatchUpdate(keys, values, nil)
}

func (x *XdpWall) DeleteMatchExt(key uint32) error {
	return x.objs.MatchExtMap.Delete(key)
}

func (x *XdpWall) UpdateBucket(key uint32, value *FilterBucket) error {
	return x.objs.BucketMap.Update(key, value, ebpf.UpdateAny)
}

func (x *XdpWall) UpdateBuckets(keys []uint32, values []FilterBucket) (int, error) {
	return x.objs.BucketMap.BatchUpdate(keys, values, nil)
}

func (x *XdpWall) DeleteBucket(key uint32) error {
	return x.objs.BucketMap.Delete(key)
}
