package trafficbus

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// ParseV4CIDRU32 resolving IPv4 to uint32. 
// example: ParseV4CIDRU32("192.168.0.1/24") returns (3232235521, 24, nil)
func ParseV4CIDRU32(addr string) (uip uint32, umask uint32, err error) {
	var (
		netIP          net.IP
		ipNet          *net.IPNet
	)

	if strings.Contains(addr, "/") {
		netIP, ipNet, err = net.ParseCIDR(addr)
		if err != nil {
			return
		}
	} else {
		netIP = net.ParseIP(addr)
	}

	ip4 := netIP.To4()
	if ip4 == nil {
		err = errors.New("invalid ip: " + addr)
		return
	}

	uip = binary.BigEndian.Uint32(ip4)
	if ipNet != nil {
		sourceMask, _ := ipNet.Mask.Size()
		umask = uint32(sourceMask)
	}

	return
}
