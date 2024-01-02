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

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printIpSet(wall *Wall, setName string) {
	ipset, err := wall.LookupIPSet(setName)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Name:\t%s\n", ipset.Name)
	fmt.Println("Addresses: ")
	for _, addr := range ipset.Addrs {
		fmt.Printf("\t%s\n", addr)
	}
}

func TestIpSet(t *testing.T) {
	wall := NewWall()

	err := wall.CreateIPSet("myset")
	fatal(err)

	err = wall.AppendIP("myset", "127.0.0.1", "0.0.0.0", "192.168.0.0/16", "1.1.1.1")
	fatal(err)

	err = wall.AppendIP("myset", "2.2.2.2")
	fatal(err)

	printIpSet(wall, "myset")

	fmt.Printf("\nRemove...\n\n")

	err = wall.RemoveIP("myset", "0.0.0.0")
	fatal(err)
	err = wall.RemoveIP("myset", "1.1.1.1")
	fatal(err)

	printIpSet(wall, "myset")
}

func printRules(wall *Wall) {
	rules, err := wall.ListRule()
	if err != nil {
		log.Fatal(err)
	}

	for i, rule := range rules {
		fmt.Printf("index: %d, interface: %s, target: %s, protocol: %s, source: %s, destination: %s\n", i, rule.Interface, rule.Target, rule.Protocol, rule.Source, rule.Destination)
	}
}

func TestRules(t *testing.T) {
	wall := NewWall()
	iface := "lo"
	data := []*Rule{
		{Interface: iface, Protocol: "ICMP"},
		{Interface: iface, Protocol: "TCP"},
		{Interface: iface, Protocol: "UDP"},
	}

	err := wall.AppendRule(data...)
	fatal(err)

	printRules(wall)

	fmt.Println("Insert...")

	err = wall.InsertRule(1, &Rule{Interface: iface, Protocol: "UDP"})
	fatal(err)

	err = wall.AppendRule(&Rule{Interface: iface, Protocol: "TCP"})
	fatal(err)

	printRules(wall)

	fmt.Println("Remove...")

	err = wall.RemoveRule(1)
	fatal(err)

	printRules(wall)
}

func TestLoadFromJson(t *testing.T) {
	wall := NewWall()
	err := wall.LoadFromJson("./testdata/rule.json")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("ipset:")
	printIpSet(wall, "myset")

	fmt.Println("rules:")
	printRules(wall)
}

func TestLoadFromYaml(t *testing.T) {}

func TestWall(t *testing.T) {
	runServers()
	wall := NewWall()
	err := wall.LoadFromJson("./testdata/rule.json")
	fatal(err)

	err = wall.Run()
	fatal(err)

	go wall.RecvMatchLogs()

	// remove an IP after few seconds to see if it can match the rules normally
	time.Sleep(10 * time.Second)
	err = wall.RemoveIP("myset", "39.156.66.10")
	fatal(err)

	select {}
}
