package trafficbus

// type TargetAction string

// const (
// 	TargetAccept = "ACCEPT"
// 	TargetDrop   = "DROP"
// 	TargetSNAT   = "SNAT"
// 	TargetDNAT   = "DNAT"
// )

type RuleNAT struct {
	Src string `json:"src"`
	Dst string `json:"dest"`
}

type ModuleNAT struct {
	Prerouting  []RuleNAT `json:"prerouting"`
	Postrouting []RuleNAT `json:"postrouting"`
}

type RuleFilter struct {
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	SrcPort  int    `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Target   string `json:"target"`
}

type ModuleFilter struct {
	Input  []RuleFilter `json:"input"`
	Output []RuleFilter `json:"output"`
}

type Modules struct {
	NAT    ModuleNAT    `json:"nat"`
	Filter ModuleFilter `json:"filter"`
}

type RuleSet struct {
	IFace   string  `json:"iface"`
	Modules Modules `json:"modules"`
}
