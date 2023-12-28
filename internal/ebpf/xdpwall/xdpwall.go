package xdpwall

import (
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ip_set_direction -target amd64 Filter xdpwall.c -- -I../include

type XdpWall struct {
	objs  FilterObjects
	links map[int]link.Link
	sync.Mutex
}

func NewXdpWall() (*XdpWall, error) {
	x := &XdpWall{
		links: make(map[int]link.Link),
	}
	err := LoadFilterObjects(&x.objs, nil)
	if err != nil {
		return nil, err
	}

	return x, nil
}

func (x *XdpWall) Stop() error {
	for iface := range x.links {
		err := x.Detach(iface)
		if err != nil {
			return err
		}
	}
	return x.objs.Close()
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
		log.Fatalf("could not attach xdp program: %s", err)
	}

	log.Printf("attached xdp program to iface index %d", iface)
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

func (x *XdpWall) UpdateIP(key FilterIpv4LpmKey, val FilterIpv4LpmKey) error {
	return x.objs.IpsetMap.Update(key, val, ebpf.UpdateAny)
}

func (x *XdpWall) UpdateIPs(keys []FilterIpv4LpmKey, values []uint32) (int, error) {
	return x.objs.IpsetMap.BatchUpdate(keys, values, nil)
}

func (x *XdpWall) RemoveIP(key FilterIpv4LpmKey) error {
	return x.objs.IpsetMap.Delete(key)
}

// UpdateRule updates a rule.
// Since the array is of constant size, deletion operations is not supported.
// To clear an array element, use Update to insert a zero value to that index.
func (x *XdpWall) UpdateRule(key uint32, value FilterRule) error {
	return x.objs.RuleMap.Update(key, value, ebpf.UpdateAny)
}

func (x *XdpWall) UpdateRules(keys []uint32, values []FilterRule) (int, error) {
	return x.objs.RuleMap.BatchUpdate(keys, values, nil)
}
