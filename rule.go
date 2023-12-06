package trafficbus

import (
	"encoding/json"
	"os"
)

type Rule struct {
	Num         int    `json:"num"`
	Target      string `json:"target"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
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
