package xdp

import (
	"fmt"
	"net"

	"github.com/cccoven/trafficbus"
)

var (
	TargetMap = map[string]bpfXdpAction{
		"DROP":     bpfXdpActionXDP_DROP,
		"PASS":     bpfXdpActionXDP_PASS,
		"TX":       bpfXdpActionXDP_TX,
		"REDIRECT": bpfXdpActionXDP_REDIRECT,
	}

	ProtocolMap = map[string]bpfProtocol{
		"ICMP": bpfProtocolICMP,
		"UDP":  bpfProtocolUDP,
		"TCP":  bpfProtocolTCP,
	}
)

func ConvertToXDPRule(ori []trafficbus.Rule) ([]bpfXdpRule, error) {
	var rules []bpfXdpRule

	for _, item := range ori {
		r := bpfXdpRule{
			Num:             uint32(item.Num),
			Pkts:            0,
			Bytes:           0,
			Target:          uint32(TargetMap[item.Target]),
			Protocol:        uint32(ProtocolMap[item.Protocol]),
			Source:          0,
			SourceMask:      0,
			Destination:     0,
			DestinationMask: 0,
		}

		sourceIP, sourceIPNet, err := net.ParseCIDR(item.Source)
		if err != nil {
			return nil, err
		}
	
		fmt.Println(sourceIP.String())
		fmt.Println(sourceIPNet.IP.String())
		fmt.Println(sourceIPNet.Mask.Size())
		
		rules = append(rules, r)
	}

	return rules, nil
}
