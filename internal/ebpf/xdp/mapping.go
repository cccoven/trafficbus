package xdp

import (
	"github.com/cccoven/trafficbus"
	"github.com/cccoven/trafficbus/internal"
)

var (
	TargetMap = map[string]bpfXdpAction{
		"DROP":     bpfXdpActionXDP_DROP,
		"ACCEPT":   bpfXdpActionXDP_PASS,
		"TX":       bpfXdpActionXDP_TX,
		"REDIRECT": bpfXdpActionXDP_REDIRECT,
	}

	ProtocolMap = map[string]bpfProtocol{
		"ICMP": bpfProtocolICMP,
		"UDP":  bpfProtocolUDP,
		"TCP":  bpfProtocolTCP,
	}
)

func ConvertToXdpRule(ori []trafficbus.Rule) ([]bpfXdpRule, error) {
	var rules []bpfXdpRule
	var err error

	for _, item := range ori {
		r := bpfXdpRule{
			Num:      uint32(item.Num),
			Target:   uint32(TargetMap[item.Target]),
			Protocol: uint32(ProtocolMap[item.Protocol]),
		}

		r.Source, r.SourceMask, err = internal.ParseV4CIDRU32(item.Source)
		if err != nil {
			return nil, err
		}

		r.Destination, r.DestinationMask, err = internal.ParseV4CIDRU32(item.Destination)
		if err != nil {
			return nil, err
		}

		if item.UDPExt != nil {
			r.UdpExt.Enable = 1
			r.UdpExt.Sport = uint16(item.UDPExt.SrcPort)
			r.UdpExt.Dport = uint16(item.UDPExt.DstPort)
		}

		rules = append(rules, r)
	}

	return rules, nil
}
