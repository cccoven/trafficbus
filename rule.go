package trafficbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	MaxIPSet = 255
	MaxRules = 3
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

type RuleSet map[string][]*Rule

type RuleStorage struct {
	ipSet   IPSet
	ruleSet RuleSet
}

func NewRuleStorage() *RuleStorage {
	return &RuleStorage{
		ipSet:   make(IPSet),
		ruleSet: make(RuleSet, MaxRules),
	}
}

func (rs *RuleStorage) GetIPSet(setName string) []string {
	return rs.ipSet[setName]
}

// AppendIP appends ip(s) to an ipset
func (rs *RuleStorage) AppendIP(setName string, ips ...string) {
	rs.ipSet[setName] = append(rs.ipSet[setName], ips...)
}

func (rs *RuleStorage) DelIP(setName, ip string) error {
	addrs, ok := rs.ipSet[setName]
	if !ok {
		return fmt.Errorf("ipset %s does not exist", setName)
	}

	for i, addr := range addrs {
		if addr == ip {
			rs.ipSet[setName] = append(rs.ipSet[setName][:i], rs.ipSet[setName][i+1:]...)
			return nil
		}
	}

	return nil
}

func (rs *RuleStorage) ClearIPSet(setName string) {
	delete(rs.ipSet, setName)
}


func (rs *RuleStorage) GetRules(iface string) []*Rule {
	return rs.ruleSet[iface]
}

// AppendRule appends rule(s) to the ruleset
func (rs *RuleStorage) AppendRule(iface string, rules ...*Rule) {
	rs.ruleSet[iface] = append(rs.ruleSet[iface], rules...)
}

func (rs *RuleStorage) InsertRule(iface string, pos int, rule *Rule) error {
	if pos < 0 {
		return errors.New("invalid position")
	}

	rules, ok := rs.ruleSet[iface]
	if pos > len(rules) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	if !ok || pos == len(rules) {
		rs.AppendRule(iface, rule)
		return nil
	}

	rs.ruleSet[iface] = append(rs.ruleSet[iface], nil)
	copy(rs.ruleSet[iface][pos+1:], rs.ruleSet[iface][pos:])
	rs.ruleSet[iface][pos] = rule

	return nil
}

func (rs *RuleStorage) DelRule(iface string, pos int) error {
	rules, ok := rs.ruleSet[iface]
	if !ok {
		return fmt.Errorf("rules for %s does not exist", iface)
	}

	if pos >= len(rules) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	rs.ruleSet[iface] = append(rules[:pos], rules[pos+1:]...)
	return nil
}

func (rs *RuleStorage) ClearRules(iface string) {
	delete(rs.ruleSet, iface)
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
