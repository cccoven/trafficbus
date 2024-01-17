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

type RuleExtension struct {
	FilterMatchExt
	Limiter *FilterBucket
}

type Rule struct {
	FilterRule
	Extension *RuleExtension
}

type Wall struct {
	objs  FilterObjects
	links map[int]link.Link
	// TODO close this reader
	rbufReader *ringbuf.Reader
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

func (w *Wall) LookupIPSet(key uint32) (IPSet, error) {
	var set IPSet
	err := w.objs.IpSetMap.Lookup(key, &set)
	if err != nil {
		return set, err
	}

	return set, nil
}

func (w *Wall) UpdateIPSet(key uint32, val IPSet) error {
	return w.objs.IpSetMap.Update(key, val, ebpf.UpdateAny)
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
				rule.Extension = &RuleExtension{}
				rule.Extension.FilterMatchExt = extension

				var bucket FilterBucket
				err = w.objs.BucketMap.Lookup(key, &bucket)
				if err == nil {
					rule.Extension.Limiter = &bucket

				}
			}
			rules = append(rules, rule)
		}
	}
	return rules
}

func (w *Wall) UpdateRule(key uint32, value *Rule) error {
	rules := w.ListRules()
	// TODO move elements here
	// w.objs.RuleMap.
	if err := w.objs.RuleMap.Update(key, value.FilterRule, ebpf.UpdateAny); err != nil {
		return err
	}
	extension := value.Extension
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

func (w *Wall) RemovRule(key uint32) error {
	if err := w.objs.RuleMap.Delete(key); err != nil {
		return err
	}
	_ = w.objs.MatchExtMap.Delete(key)
	_ = w.objs.BucketMap.Delete(key)
	return nil
}

// UpdateRule updates a rule.
// Since the array is of constant size, deletion operations is not supported.
// To clear an array element, use Update to insert a zero value to that index.
// func (w *Wall) UpdateRule(key uint32, value *FilterRule) error {
// 	if value == nil {
// 		value = &FilterRule{}
// 	}
// 	return w.objs.RuleMap.Update(key, value, ebpf.UpdateAny)
// }

// func (w *Wall) UpdateRules(keys []uint32, values []FilterRule) (int, error) {
// 	return w.objs.RuleMap.BatchUpdate(keys, values, nil)
// }

// func (w *Wall) UpdateMatchExt(key uint32, value *FilterMatchExt) error {
// 	return w.objs.MatchExtMap.Update(key, value, ebpf.UpdateAny)
// }

// func (w *Wall) UpdateMatchExts(keys []uint32, values []FilterMatchExt) (int, error) {
// 	return w.objs.MatchExtMap.BatchUpdate(keys, values, nil)
// }

// func (w *Wall) DeleteMatchExt(key uint32) error {
// 	return w.objs.MatchExtMap.Delete(key)
// }

// func (w *Wall) UpdateBucket(key uint32, value *FilterBucket) error {
// 	return w.objs.BucketMap.Update(key, value, ebpf.UpdateAny)
// }

// func (w *Wall) UpdateBuckets(keys []uint32, values []FilterBucket) (int, error) {
// 	return w.objs.BucketMap.BatchUpdate(keys, values, nil)
// }

// func (w *Wall) DeleteBucket(key uint32) error {
// 	return w.objs.BucketMap.Delete(key)
// }
