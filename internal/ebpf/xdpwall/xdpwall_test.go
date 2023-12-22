package xdpwall

import (
	"fmt"
	"log"
	"net"
	"testing"
	"time"
)

func echoServerTCP(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("error listening: ", err.Error())
		return
	}
	defer listener.Close()
	fmt.Printf("TCP server listening on addr %s\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("error accepting: ", err.Error())
			return
		}

		go func(conn net.Conn) {
			defer conn.Close()
			buffer := make([]byte, 1024)
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}

				fmt.Printf("TCP %s received: %s\n", conn.LocalAddr().String(), string(buffer[:n]))
				_, err = conn.Write(buffer[:n])
				if err != nil {
					fmt.Printf("TCP %s error writing: %s\n", addr, err.Error())
					return
				}
			}
		}(conn)
	}
}

func echoServerUDP(addr string) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("error resolving UDP address: ", err.Error())
		return
	}

	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		fmt.Println("error listening: ", err.Error())
		return
	}
	defer conn.Close()
	fmt.Printf("UDP server listening on addr %s\n", addr)

	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		fmt.Printf("UDP received message: addr=%s, msg=%s\n", conn.LocalAddr().String(), string(buffer[:n]))
		_, err = conn.WriteToUDP(buffer[:n], addr)
		if err != nil {
			fmt.Printf("UDP %s error writing: %s\n", addr, err.Error())
			return
		}
	}
}

func echoClientTCP(addr, msg string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("Error connecting:", err.Error())
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte(msg))
	if err != nil {
		fmt.Println("Error sending:", err.Error())
		return
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer[:])
	if err != nil {
		fmt.Println("Error receiving:", err.Error())
		return
	}

	fmt.Println("TCP response from server:", string(buffer[:n]))
}

func echoClientUDP(addr, msg string) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal("Error resolving UDP address:", err.Error())
	}

	conn, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		fmt.Printf("UDP %s error connecting: %s\n", addr, err.Error())
		return
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		fmt.Printf("UDP %s error sending: %s\n", addr, err.Error())
		return
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("timeout:", err.Error())
		}
		fmt.Printf("UDP %s error receiving: %s\n", addr, err.Error())
		return
	}

	fmt.Printf("UDP %s response from server: %s\n", addr, string(buffer[:n]))
}

func runServers() {
	go echoServerTCP(":8080")
	go echoServerUDP(":8081")
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		for range ticker.C {
			go echoClientTCP("127.0.0.1:8080", "hello TCP")
			go echoClientUDP("127.0.0.1:8081", "hello UDP")
		}
	}()
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ipset_direction -type ipset_item -type rule_item -target amd64 bpf xdpwall.c -- -I../include
func TestXdpWall(t *testing.T) {
	runServers()
	wall := NewXdpWall()

	data := map[string][]Rule{
		"lo": {
			{
				Enable:   1,
				Target:   uint32(bpfTargetDROP),
				Protocol: uint32(bpfProtocolICMP),
			},
			{
				Enable:   1,
				Target:   uint32(bpfTargetACCEPT),
				Protocol: uint32(bpfProtocolTCP),
			},
			{
				Enable:   1,
				Target:   uint32(bpfTargetDROP),
				Protocol: uint32(bpfProtocolUDP),
			},
		},
		// "ens3": {},
	}
	data["lo"][1].MatchExt.Enable = 1
	data["lo"][1].MatchExt.Tcp.Enable = 1
	data["lo"][1].MatchExt.Tcp.Dport = 8080
	data["lo"][2].MatchExt.Enable = 1
	data["lo"][2].MatchExt.Udp.Enable = 1
	data["lo"][2].MatchExt.Udp.Dport = 8081

	for iface, rules := range data {
		for i, rule := range rules {
			err := wall.InsertRule(iface, i, rule)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	// wall.DeleteRule("lo", 2)

	wall.Attach("lo")

	select {}
}
