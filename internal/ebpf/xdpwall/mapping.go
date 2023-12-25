package xdpwall



// func ConvertToXdpRule(ori []trafficbus.Rule) ([]bpfXdpRule, error) {
// 	var rules []bpfXdpRule
// 	var err error

// 	for _, item := range ori {
// 		r := bpfXdpRule{
// 			Enable:   1,
// 			Num:      uint32(item.Num - 1),
// 			Target:   uint32(TargetMap[item.Target]),
// 			Protocol: uint32(ProtocolMap[item.Protocol]),
// 		}

// 		r.Source, r.SourceMask, err = internal.ParseV4CIDRU32(item.Source)
// 		if err != nil {
// 			return nil, err
// 		}

// 		r.Destination, r.DestinationMask, err = internal.ParseV4CIDRU32(item.Destination)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if item.MatchExtension != nil {
// 			r.MatchExt.Enable = 1

// 			if item.MatchExtension.Set != nil {
// 				r.MatchExt.Set.Enable = 1
// 				r.MatchExt.Set.Direction = int32(IPSetTypeMap[item.MatchExtension.Set.Direction])
// 			}

// 			if item.MatchExtension.UDP != nil {
// 				r.MatchExt.Udp.Enable = 1
// 				r.MatchExt.Udp.Sport = uint16(item.MatchExtension.UDP.SrcPort)
// 				r.MatchExt.Udp.Dport = uint16(item.MatchExtension.UDP.DstPort)
// 			}

// 			if item.MatchExtension.TCP != nil {
// 				r.MatchExt.Tcp.Enable = 1
// 				r.MatchExt.Tcp.Sport = uint16(item.MatchExtension.TCP.SrcPort)
// 				r.MatchExt.Tcp.Dport = uint16(item.MatchExtension.TCP.DstPort)
// 			}
// 		}

// 		rules = append(rules, r)
// 	}

// 	return rules, nil
// }
