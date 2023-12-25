package xdpwall

import (
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"github.com/cccoven/trafficbus/internal"
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

func printRuleSet(wall *XdpWall, iface string) {
	ruleSet, err := wall.LookupRuleSet("lo")
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < int(ruleSet.Count); i++ {
		item := ruleSet.Items[i]
		fmt.Printf("idx: %d, target: %d, protocol: %d\n", i, item.Target, item.Protocol)
	}
}

func TestXdpWallRuleSet(t *testing.T) {
	wall := NewXdpWall()
	data := map[string][]FilterRuleItem{
		"lo": {
			{
				Enable:   1,
				Target:   FilterTargetDROP,
				Protocol: FilterProtocolICMP,
			},
			{
				Enable:   1,
				Target:   FilterTargetACCEPT,
				Protocol: FilterProtocolTCP,
				MatchExt: FilterMatchExt{
					Enable: 1,
					Tcp: FilterTcpExt{
						Enable: 1,
						Dport:  8080,
					},
				},
			},
			{
				Enable:   1,
				Target:   FilterTargetDROP,
				Protocol: FilterProtocolUDP,
				MatchExt: FilterMatchExt{
					Enable: 1,
					Udp: FilterUdpExt{
						Enable: 1,
						Dport:  8081,
					},
				},
			},
		},
	}

	for iface, rules := range data {
		err := wall.CreateRuleSet(iface)
		if err != nil {
			t.Fatal(err)
		}
		for i, rule := range rules {
			err = wall.InsertRule(iface, i, rule)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	printRuleSet(wall, "lo")

	fmt.Println("Insert...")

	err := wall.InsertRule("lo", 1, FilterRuleItem{
		Enable:   1,
		Target:   FilterTargetACCEPT,
		Protocol: FilterProtocolUDP,
	})
	if err != nil {
		t.Fatal(err)
	}

	wall.AppendRule("lo", FilterRuleItem{
		Enable: 1,
		Target: FilterTargetACCEPT,
	})

	printRuleSet(wall, "lo")

	fmt.Println("Remove...")

	wall.RemoveRule("lo", 1)

	printRuleSet(wall, "lo")
}

func printIpSet(wall *XdpWall, setName string) {
	ipSet, err := wall.LookupIpSet(setName)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < int(ipSet.Count); i++ {
		item := ipSet.Items[i]
		fmt.Printf("idx: %d, item: %+v\n", i, item)
	}
}

func TestXdpWallIpSet(t *testing.T) {
	wall := NewXdpWall()

	err := wall.CreateIpSet("myset")
	if err != nil {
		t.Fatal(err)
	}

	err = wall.AppendIp("myset", "127.0.0.1", "0.0.0.0", "192.168.0.0/16", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	printIpSet(wall, "myset")

	err = wall.RemoveIp("myset", "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Remove...")

	printIpSet(wall, "myset")
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type target -type protocol -type ip_set_direction -type ip_item -type rule_item -type match_ext -type set_ext -type udp_ext -type tcp_ext -type target_ext -target amd64 Filter xdpwall.c -- -I../include
func TestXdpWall(t *testing.T) {
	runServers()
	wall := NewXdpWall()
	wall.CreateIpSet("myset")
	wall.AppendIp("myset", "127.0.0.1/8")

	wall.CreateRuleSet("lo")
	wall.AppendRule("lo", FilterRuleItem{
		Enable:   1,
		Target:   FilterTargetDROP,
		Protocol: FilterProtocolICMP,
		Source:   internal.IPToInt("127.0.0.1"),
		MatchExt: FilterMatchExt{
			Enable: 1,
			Set: FilterSetExt{
				Enable:    1,
				Id:        wall.genSetID("myset"),
				Direction: FilterIpSetDirectionSRC,
			},
		},
	})

	wall.Attach("lo")

	select {}
}
