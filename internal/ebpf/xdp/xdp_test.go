package xdp

import (
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"github.com/cccoven/trafficbus"
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

				fmt.Println("TCP received: ", string(buffer[:n]))
				_, err = conn.Write(buffer[:n])
				if err != nil {
					fmt.Println("error writing: ", err.Error())
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

		fmt.Println("UDP received: ", string(buffer[:n]))
		_, err = conn.WriteToUDP(buffer[:n], addr)
		if err != nil {
			fmt.Println("error writing: ", err.Error())
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
		fmt.Println("Error resolving UDP address:", err.Error())
		return
	}

	conn, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		fmt.Println("error connecting:", err.Error())
		return
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		fmt.Println("error sending:", err.Error())
		return
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("timeout:", err.Error())
		}
		fmt.Println("error receiving:", err.Error())
		return
	}

	fmt.Println("UDP response from server:", string(buffer[:n]))
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type xdp_action -type protocol -target amd64 bpf xdp.c -- -I../include
func TestXdp(t *testing.T) {
	go echoServerTCP("127.0.0.1:8080")
	go echoServerUDP("127.0.0.1:8081")

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		for range ticker.C {
			go echoClientTCP("127.0.0.1:8080", "hello TCP")
			go echoClientUDP("127.0.0.1:8081", "hello UDP")
		}
	}()

	ruleSet, err := trafficbus.LoadRuleSetFromJSON("../../../testdata/rule.json")
	if err != nil {
		t.Fatal("failed to load rule from json: ", err)
	}

	for _, item := range ruleSet {
		go func(rs trafficbus.RuleSet) {
			rules, err := ConvertToXdpRule(rs.Rules)
			if err != nil {
				log.Fatal("failed to convert rule: ", err)
			}
			xdpProg := NewXdp(rs.IFace, rules)
			xdpProg.Run()
		}(item)
	}

	select {}
}
