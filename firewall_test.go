package trafficbus

import (
	"errors"
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

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// func printIPSet(wall *Wall, setName string) {
// 	set, err := wall.LookupIPSet(setName)
// 	fatal(err)

// 	setRaw, err := wall.xdp.LookupIPSet(str2hash(setName))
// 	fatal(err)

// 	for i, addr := range set.Addrs {
// 		fmt.Printf("addr: %-20sraw: %-20s\n", addr, internal.IntToIP(setRaw[i].Addr))
// 	}
// }

// func TestIPSet(t *testing.T) {
// 	wall := NewWall(&WallOptions{})

// 	err := wall.CreateIPSet("myset")
// 	fatal(err)

// 	err = wall.AppendIP("myset", "127.0.0.1", "0.0.0.0", "192.168.0.0/16", "1.1.1.1")
// 	fatal(err)

// 	err = wall.AppendIP("myset", "2.2.2.2")
// 	fatal(err)

// 	printIPSet(wall, "myset")

// 	fmt.Printf("\nRemove...\n\n")

// 	err = wall.RemoveIP("myset", "0.0.0.0")
// 	fatal(err)
// 	err = wall.RemoveIP("myset", "1.1.1.1")
// 	fatal(err)

// 	printIPSet(wall, "myset")
// }

func printRules(wall *Firewall) {
	rules := wall.ListRules()
	rulesRaw := wall.xdp.ListRules()
	if len(rules) != len(rulesRaw) {
		fatal(errors.New("the lenth of rules is inconsistent"))
	}

	for i, rule := range rules {
		var limitCap, limitCapRaw uint64
		if rule.MatchExtension != nil {
			if rule.MatchExtension.Limit != "" {
				b, err := wall.converter.ParseLimit(rule.MatchExtension.Limit)
				if err != nil {
					fatal(err)
				}
				limitCap = b.Capacity
			}
		}

		if rulesRaw[i].MatchExtension != nil {
			limitCapRaw = rulesRaw[i].MatchExtension.Limiter.Capacity
		}
		fmt.Printf(
			"iface: %s/%-10dprot: %s/%-10dsrc: %s/%-10slimit: %d/%-10d\n",
			rule.Interface,
			rulesRaw[i].Interface,
			rule.Protocol,
			rulesRaw[i].Protocol,
			rule.Source,
			internal.IntToIP(rulesRaw[i].Source),
			limitCap,
			limitCapRaw,
		)
	}
}

func TestRules(t *testing.T) {
	wall := NewFirewall()
	iface := "lo"
	data := []*Rule{
		{
			Interface: iface,
			Protocol:  "ICMP",
			MatchExtension: &MatchExtension{
				Limit: "5/second",
			},
		},
		{
			Interface: iface,
			Protocol:  "TCP",
			MatchExtension: &MatchExtension{
				Limit: "10/minute",
			},
		},
		{
			Interface: iface,
			Protocol:  "UDP",
			MatchExtension: &MatchExtension{
				Limit: "15/hour",
			},
		},
	}

	err := wall.AppendRule(data...)
	fatal(err)

	printRules(wall)

	fmt.Println("Insert...")

	err = wall.InsertRule(1, &Rule{
		Interface: iface,
		Protocol:  "UDP",
		MatchExtension: &MatchExtension{
			Limit: "6/second",
		},
	})
	fatal(err)

	err = wall.AppendRule(&Rule{
		Interface: iface,
		Protocol:  "TCP",
		MatchExtension: &MatchExtension{
			Limit: "7/second",
		},
	})
	fatal(err)
	err = wall.AppendRule(&Rule{
		Interface: iface,
		Protocol:  "ICMP",
	})
	fatal(err)

	printRules(wall)

	fmt.Println("Remove...")

	err = wall.DeleteRule(1)
	fatal(err)
	err = wall.DeleteRule(0)
	fatal(err)
	err = wall.DeleteRule(2)
	fatal(err)
	err = wall.DeleteRule(2)
	fatal(err)

	printRules(wall)
}

// func TestLoadFromJson(t *testing.T) {
// 	wall := NewWall(&WallOptions{})
// 	err := wall.LoadFromJson("./testdata/rule.json")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	fmt.Println("ipSet:")
// 	printIPSet(wall, "myset")

// 	fmt.Println("rules:")
// 	printRules(wall)
// }

func TestLoadFromYaml(t *testing.T) {
	wall := NewFirewall()
	err := wall.LoadFromYaml("./testdata/rule.yaml")
	if err != nil {
		t.Fatal(err)
	}

	// fmt.Println("ipSet:")
	// printIPSet(wall, "myset")

	fmt.Println("rules:")
	printRules(wall)
}

func TestFirewall(t *testing.T) {
	runServers()
	wall := NewFirewall()
	err := wall.LoadFromYaml("./testdata/rule.yaml")
	fatal(err)

	wall.Run()

	// // remove an IP after few seconds to see if it can match the rules normally
	// time.Sleep(10 * time.Second)
	// // err = wall.RemoveIP("myset", "39.156.66.10")
	// // fatal(err)

	// wall.Stop()

	// select {}
}
