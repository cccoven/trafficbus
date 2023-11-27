package xdp

import (
	"log"
	"net"

	"github.com/cilium/ebpf/link"
)

// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf xdp.c -- -I../include

func Demo(ifaceName string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
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

	// rd, err := ringbuf.NewReader(objs.Myevents)
	// if err != nil {
	// 	log.Fatalf("opening ringbuf reader: %s", err)
	// }
	// defer rd.Close()

	// var event bpfEvent
	// for {
	// 	record, err := rd.Read()
	// 	if err != nil {
	// 		if errors.Is(err, ringbuf.ErrClosed) {
	// 			log.Println("Received signal, exiting..")
	// 			return
	// 		}
	// 		log.Printf("reading from reader: %s", err)
	// 		continue
	// 	}

	// 	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	// 	if err != nil {
	// 		log.Printf("parsing ringbuf event: %s", err)
	// 		continue
	// 	}

	// 	log.Printf("id: %d\n", event.Id)
	// 	fmt.Println(event.Ids)
	// 	unix.ByteSliceToString(event.Name[:])
	// 	fmt.Printf("%s\n", event.Name)
	// }

	// Print the contents of the BPF hash map (source IP address -> packet count).
	// ticker := time.NewTicker(1 * time.Second)
	// defer ticker.Stop()
	// for range ticker.C {
	// 	var key bpfKey
	// 	var value bpfValue
	// 	it := objs.XdpMap.Iterate()
	// 	for it.Next(&key, &value) {
	// 		fmt.Println(unix.ByteSliceToString(key.Name[:]), ", ", value)
	// 	}
	// }
}
