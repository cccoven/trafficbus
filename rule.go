package trafficbus

import (
	"encoding/json"
	"fmt"
	"os"
)

type IPSet map[string][]string

type SetExtension struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

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
	Set    *SetExtension `json:"set,omitempty"`
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

type RuleSet map[string][]Rule

type RuleStorage struct {
	ipSet   IPSet
	ruleSet RuleSet
}

func NewRuleStorage() *RuleStorage {
	return &RuleStorage{}
}

func (rs *RuleStorage) GetIPSet(setName string) []string {
	return rs.ipSet[setName]
}

func (rs *RuleStorage) AddIPSet(setName string, addrs []string) error {
	if rs.GetIPSet(setName) != nil {
		return fmt.Errorf("ipset %s already exists", setName)
	}
	rs.ipSet[setName] = addrs
	return nil
}

func (rs *RuleStorage) DelIPSet(setName string) {
	delete(rs.ipSet, setName)
}

func (rs *RuleStorage) GetRules(iface string) []Rule {
	return rs.ruleSet[iface]
}

func (rs *RuleStorage) AddRules(iface string, rules []Rule) error {
	if rs.GetRules(iface) != nil {
		return fmt.Errorf("rules %s already exists", iface)
	}
	rs.ruleSet[iface] = rules
	return nil
}

func (rs *RuleStorage) DelRules(iface string) {
	delete(rs.ruleSet, iface)
}

func (rs *RuleStorage) InsertRule(iface string, num int, rule Rule) {
	// TODO
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
