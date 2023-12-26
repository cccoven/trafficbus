package trafficbus

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

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printIpSet(wall *Wall, setName string) {
	ipSet, err := wall.LookupIpSet(setName)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Name:\t%s\n", ipSet.Name)
	fmt.Println("Addresses: ")
	for _, addr := range ipSet.Addrs {
		fmt.Printf("\t%s\n", addr)
	}
}

func TestIPSet(t *testing.T) {
	wall := NewWall()

	err := wall.CreateIpSet("myset")
	handleError(err)

	err = wall.AppendIp("myset", "127.0.0.1", "0.0.0.0", "192.168.0.0/16", "1.1.1.1")
	handleError(err)

	printIpSet(wall, "myset")

	fmt.Printf("\nRemove...\n\n")

	err = wall.RemoveIp("myset", "0.0.0.0")
	handleError(err)
	err = wall.RemoveIp("myset", "1.1.1.1")
	handleError(err)

	printIpSet(wall, "myset")
}

func printRuleSet(wall *Wall, iface string) {
	rules, err := wall.LookupRuleSet(iface)
	if err != nil {
		log.Fatal(err)
	}

	for i, rule := range rules {
		fmt.Printf("index: %d, target: %s, protocol: %s, source: %s, destination: %s\n", i, rule.Target, rule.Protocol, rule.Source, rule.Destination)
	}
}

func TestRuleSet(t *testing.T) {
	runServers()
	wall := NewWall()
	data := map[string][]*Rule{
		"lo": {
			{
				Target:   "DROP",
				Protocol: "ICMP",
			},
			{
				Target:   "ACCEPT",
				Protocol: "TCP",
				MatchExtension: MatchExtension{
					TCP: TCPExtension{
						DstPort: 8080,
					},
				},
			},
			{
				Target:   "DROP",
				Protocol: "UDP",
				MatchExtension: MatchExtension{
					UDP: UDPExtension{
						DstPort: 8081,
					},
				},
			},
		},
	}

	for iface, rules := range data {
		err := wall.CreateRuleSet(iface)
		handleError(err)
		for i, rule := range rules {
			err = wall.InsertRule(iface, i, rule)
			handleError(err)
		}
	}

	printRuleSet(wall, "lo")

	fmt.Println("Insert...")

	err := wall.InsertRule("lo", 1, &Rule{
		Target:   "ACCEPT",
		Protocol: "UDP",
		Source:   "127.0.0.0/8",
	})
	handleError(err)

	err = wall.AppendRule("lo", &Rule{Target: "ACCEPT"})
	handleError(err)

	printRuleSet(wall, "lo")

	fmt.Println("Remove...")

	wall.RemoveRule("lo", 1)

	printRuleSet(wall, "lo")
}

func TestLoadFromJSON(t *testing.T) {
	wall := NewWall()
	err := wall.LoadFromJson("./testdata/rule.json")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("ipSet:")
	printIpSet(wall, "myset")

	fmt.Println("ruleSet:")
	printRuleSet(wall, "lo")
}

func TestLoadFromYaml(t *testing.T) {}

func TestWall(t *testing.T) {
	runServers()
	wall := NewWall()
	err := wall.LoadFromJson("./testdata/rule.json")
	if err != nil {
		t.Fatal(err)
	}

	err = wall.Run()
	if err != nil {
		t.Fatal(err)
	}

	select {}
}
