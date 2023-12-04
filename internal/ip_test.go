package internal

import (
	"fmt"
	"testing"
)

func TestParseV4CIDRU32(t *testing.T) {
	ips := []string{"39.156.66.10", "192.168.0.1/24", "0.0.0.0/0", "123.123.123.123/8", "1.1."}
	for _, ip := range ips {
		i, m, err := ParseV4CIDRU32(ip)
		fmt.Printf("ip: %d, mask: %d\n", i, m)
		if err != nil {
			t.Fatal(err.Error())
		}
	}
}
