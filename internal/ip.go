package internal

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// ParseV4CIDRU32 resolving IPv4 to uint32.
// For compatibility, all bytes are in network byte order(big endian).
// example:
// ParseV4CIDRU32("192.168.0.1/24") returns (3232235521, ffffff00, nil)
func ParseV4CIDRU32(addr string) (uip uint32, umask uint32, err error) {
	if addr == "" {
		return
	}
	var (
		netIP net.IP
		ipNet *net.IPNet
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
		maskSize, _ := ipNet.Mask.Size()
		if maskSize > 0 {
			bits := uint32(0xffffffff << (32 - maskSize))
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, bits)
			umask = binary.BigEndian.Uint32(buf)
		}
	}

	return
}
