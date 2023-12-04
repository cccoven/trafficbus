package trafficbus

import (
	"encoding/json"
	"log"
	"os"
)

type Rule struct {
	Num         int    `json:"num,omitempty"`
	Target      string `json:"target"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type RuleSet struct {
	IFace string `json:"iface"`
	Rules []Rule `json:"rules"`
}

func LoadRuleSetFromJSON(f string) []RuleSet {
	data, err := os.ReadFile(f)
	if err != nil {
		log.Fatal("failed to read rule file: ", err.Error())
	}

	var rs []RuleSet
	err = json.Unmarshal(data, &rs)
	if err != nil {
		log.Fatal("failed to load rule data: ", err.Error())
	}

	return rs;
}
