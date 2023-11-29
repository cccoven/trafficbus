package xdp

import (
	"log"
	"net"
	"time"

	"github.com/cccoven/trafficbus"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdp xdp.c -- -I../include

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
	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
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

	var name [20]byte
	str := "PREROUTING" // 长度为10的字符串
	copy(name[:], str) // 将字符串转换为字节数组

	objs.TableMap.Put(&name, uint32(100))

	// objs.TableMap.Put(uint32(1), uint32(100))

	for {
		time.Sleep(1)
	}
}
