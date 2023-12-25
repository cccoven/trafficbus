package trafficbus

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cccoven/trafficbus/internal/ebpf/xdpwall"
)

var (
	xdpTargetMap = map[string]xdpwall.FilterTarget{
		"DROP":    xdpwall.FilterTargetDROP,
		"ACCEPT":  xdpwall.FilterTargetACCEPT,
		"TX":      xdpwall.FilterTargetTX,
		"FORWARD": xdpwall.FilterTargetFORWARD,
		"LOG":     xdpwall.FilterTargetLOG,
	}

	xdpProtocolMap = map[string]xdpwall.FilterProtocol{
		"ICMP": xdpwall.FilterProtocolICMP,
		"UDP":  xdpwall.FilterProtocolUDP,
		"TCP":  xdpwall.FilterProtocolTCP,
	}

	xdpIpSetTypeMap = map[string]xdpwall.FilterIpSetDirection{
		"SRC":  xdpwall.FilterIpSetDirectionSRC,
		"DST":  xdpwall.FilterIpSetDirectionDST,
		"BOTH": xdpwall.FilterIpSetDirectionBOTH,
	}
)

type IpSetEntry struct {
	Name  string
	Addrs []string
}

type IpSet map[string]*IpSetEntry

type SetExtension struct {
	Enable    int    `json:"enable" yaml:"enable"`
	Name      string `json:"name" yaml:"name"`
	Direction string `json:"direction" yaml:"direction"`
}

type UDPExtension struct {
	Enable  int `json:"enable" yaml:"enable"`
	SrcPort int `json:"srcPort" yaml:"srcPort"`
	DstPort int `json:"dstPort" yaml:"dstPort"`
}

type TCPExtension struct {
	Enable  int `json:"enable" yaml:"enable"`
	SrcPort int `json:"srcPort" yaml:"srcPort"`
	DstPort int `json:"dstPort" yaml:"dstPort"`
}

type MatchExtension struct {
	Enable int           `json:"enable" yaml:"enable"`
	Set    *SetExtension `json:"set,omitempty" yaml:"set"`
	UDP    *UDPExtension `json:"udp,omitempty" yaml:"udp"`
	TCP    *TCPExtension `json:"tcp,omitempty" yaml:"tcp"`
}

type TargetExtension struct{}

type Rule struct {
	Num             int             `json:"num" yaml:"num"`
	Target          string          `json:"target" yaml:"target"`
	Protocol        string          `json:"protocol" yaml:"protocol"`
	Source          string          `json:"source" yaml:"source"`
	Destination     string          `json:"destination" yaml:"destination"`
	MatchExtension  *MatchExtension `json:"matchExtension,omitempty" yaml:"matchExtension"`
	TargetExtension *TCPExtension   `json:"targetExtension,omitempty" yaml:"targetExtension"`
}

type RuleSet map[string][]*Rule

type RuleFormat struct {
	IpSets   []*IpSetEntry `json:"ipSets" yaml:"ipSets"`
	RuleSets []*struct {
		Iface string  `json:"iface" yaml:"iface"`
		Rules []*Rule `json:"rules" yaml:"rules"`
	} `json:"ruleSets" yaml:"ruleSets"`
}

type Wall struct {
	ipSets   IpSet
	ruleSets RuleSet

	xdp *xdpwall.XdpWall
}

func NewWall() *Wall {
	w := &Wall{
		ipSets:   make(IpSet),
		ruleSets: make(RuleSet),
	}

	w.xdp = xdpwall.NewXdpWall()

	return w
}

func (w *Wall) syncXdpIPSet(setName string) error {
	// entry := w.GetIPSet(setName)
	// nameh := w.str2hash(setName)
	// if entry == nil {
	// 	// delete ipset
	// 	w.xdp.DelIPSet(nameh)
	// 	return nil
	// }

	// var kvs []xdpwall.IPSetKV
	// if len(entry.Addrs) == 0 {
	// 	// clear ipset
	// 	w.xdp.SetIPSet(nameh, kvs)
	// 	return nil
	// }

	// for _, addr := range entry.Addrs {
	// 	ip, mask, err := internal.ParseV4CIDRU32(addr)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	kv := xdpwall.IPSetKV{
	// 		Key: xdpwall.IPSetKey{
	// 			Prefixlen: 32,
	// 			Data:      ip,
	// 		},
	// 		Value: xdpwall.IPSetVal{
	// 			Addr: ip,
	// 			Mask: mask,
	// 		},
	// 	}
	// 	kvs = append(kvs, kv)
	// }

	// w.xdp.SetIPSet(nameh, kvs)

	return nil
}

func (w *Wall) GetIPSet(setName string) *IpSetEntry {
	return w.ipSets[setName]
}

func (w *Wall) SetIPSet(setName string, entry *IpSetEntry) {
	w.ipSets[setName] = entry
	w.syncXdpIPSet(setName)
}

// AppendIP appends ip(s) to an ipset
func (w *Wall) AppendIP(setName string, ips ...string) {
	entry := w.GetIPSet(setName)
	if entry == nil {
		entry = &IpSetEntry{Name: setName}
	}
	entry.Addrs = append(entry.Addrs, ips...)
	w.syncXdpIPSet(setName)
}

func (w *Wall) DelIP(setName, ip string) error {
	entry := w.GetIPSet(setName)
	if entry == nil {
		return fmt.Errorf("ipset %s does not exist", setName)
	}

	for i, addr := range entry.Addrs {
		if addr == ip {
			entry.Addrs = append(entry.Addrs[:i], entry.Addrs[i+1:]...)
			break
		}
	}

	w.syncXdpIPSet(setName)

	return nil
}

func (w *Wall) DelIPSet(setName string) {
	delete(w.ipSets, setName)
	w.syncXdpIPSet(setName)
}

func (w *Wall) GetRules(iface string) []*Rule {
	return w.ruleSets[iface]
}

func (w *Wall) SetRules(iface string, rules []*Rule) {
	w.ruleSets[iface] = rules
}

// AppendRule appends rule(s) to the ruleset
func (w *Wall) AppendRule(iface string, rules ...*Rule) {
	w.ruleSets[iface] = append(w.ruleSets[iface], rules...)
}

func (w *Wall) InsertRule(iface string, pos int, rule *Rule) error {
	if pos < 0 {
		return fmt.Errorf("invalid position %d", pos)
	}

	rules, ok := w.ruleSets[iface]
	if pos > len(rules) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	if !ok || pos == len(rules) {
		w.AppendRule(iface, rule)
		return nil
	}

	w.ruleSets[iface] = append(w.ruleSets[iface], nil)
	copy(w.ruleSets[iface][pos+1:], w.ruleSets[iface][pos:])
	w.ruleSets[iface][pos] = rule

	return nil
}

func (w *Wall) DelRule(iface string, pos int) error {
	rules, ok := w.ruleSets[iface]
	if !ok {
		return fmt.Errorf("rules for %s does not exist", iface)
	}

	if pos >= len(rules) {
		return fmt.Errorf("position %d is out of range", pos)
	}

	w.ruleSets[iface] = append(rules[:pos], rules[pos+1:]...)
	return nil
}

func (w *Wall) DelRules(iface string) {
	delete(w.ruleSets, iface)
}

func (w *Wall) LoadFromJSON(f string) error {
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}

	var ruleFormat RuleFormat
	err = json.Unmarshal(data, &ruleFormat)
	if err != nil {
		return err
	}

	// fill ipset
	for _, ipSet := range ruleFormat.IpSets {
		if w.GetIPSet(ipSet.Name) != nil {
			return fmt.Errorf("ipset %s already exists", ipSet.Name)
		}
		w.SetIPSet(ipSet.Name, ipSet)
	}

	// fill ruleset
	for _, ruleSet := range ruleFormat.RuleSets {
		if w.GetRules(ruleSet.Iface) != nil {
			return fmt.Errorf("ruleset %s already exists", ruleSet.Iface)
		}
		w.SetRules(ruleSet.Iface, ruleSet.Rules)
	}

	return nil
}

func (w *Wall) Run() {

}
