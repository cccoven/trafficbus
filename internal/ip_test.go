package internal

import (
	"fmt"
	"testing"
)

func TestParseV4CIDRU32(t *testing.T) {
	ips := []string{
		"39.23.45.64",
		"192.168.1.0/24",
		"192.168.0.123",
		"192.168.1.10",
		"0.0.0.0/0",
		"123.123.123.123/8",
		"1.1.1.1",
		"127.0.0.1",
		"",
	}
	for _, ip := range ips {
		i, m, err := ParseV4CIDRU32(ip)
		fmt.Printf("ipstr: %s,\tip: %d,\tmask: %x\n", ip, i, m)
		if err != nil {
			t.Error(err.Error())
		}
	}
}

func TestUintToIP(t *testing.T) {
	ip := UintToIP(2130706433)

	if ip.String() != "127.0.0.1" {
		t.Fatal("error ip")
	}

	fmt.Println(ip.String())
}
