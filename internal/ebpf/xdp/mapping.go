package xdp

import "github.com/cccoven/trafficbus"

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

	return rules, nil
}
