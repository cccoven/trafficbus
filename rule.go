package trafficbus

import (
	"encoding/json"
	"os"
)

type UDPExtension struct {
	Enable  int `json:"enable"`
	SrcPort int `json:"src_port"`
	DstPort int `json:"dst_port"`
}

type TCPExtension struct {
	Enable  int `json:"enable"`
	SrcPort int `json:"src_port"`
	DstPort int `json:"dst_port"`
}

type MatchExtension struct {
	Enable int           `json:"enable"`
	UDP    *UDPExtension `json:"udp,omitempty"`
	TCP    *TCPExtension `json:"tcp,omitempty"`
}

type TargetExtension struct{}

type Rule struct {
	Num             int             `json:"num"`
	Target          string          `json:"target"`
	Protocol        string          `json:"protocol"`
	Source          string          `json:"source"`
	Destination     string          `json:"destination"`
	MatchExtension  *MatchExtension `json:"match_extension,omitempty"`
	TargetExtension *TCPExtension   `json:"target_extension,omitempty"`
}

type RuleSet struct {
	IFace string `json:"iface"`
	Rules []Rule `json:"rules"`
}

func LoadRuleSetFromJSON(f string) ([]RuleSet, error) {
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}

	var rs []RuleSet
	err = json.Unmarshal(data, &rs)
	if err != nil {
		return nil, err
	}

	return rs, nil
}
