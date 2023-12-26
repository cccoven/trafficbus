package trafficbus

import (
	"encoding/json"
	"os"

	"github.com/cccoven/trafficbus/internal"
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

type IpSet struct {
	Name  string
	Addrs []string
}

type SetExtension struct {
	Name      string `json:"name" yaml:"name"`
	Direction string `json:"direction" yaml:"direction"`
}

type UDPExtension struct {
	SrcPort int `json:"srcPort" yaml:"srcPort"`
	DstPort int `json:"dstPort" yaml:"dstPort"`
}

type TCPExtension struct {
	SrcPort int `json:"srcPort" yaml:"srcPort"`
	DstPort int `json:"dstPort" yaml:"dstPort"`
}

type MatchExtension struct {
	Set SetExtension `json:"set,omitempty" yaml:"set"`
	UDP UDPExtension `json:"udp,omitempty" yaml:"udp"`
	TCP TCPExtension `json:"tcp,omitempty" yaml:"tcp"`
}

type TargetExtension struct{}

type Rule struct {
	Num             int            `json:"num" yaml:"num"`
	Target          string         `json:"target" yaml:"target"`
	Protocol        string         `json:"protocol" yaml:"protocol"`
	Source          string         `json:"source" yaml:"source"`
	Destination     string         `json:"destination" yaml:"destination"`
	MatchExtension  MatchExtension `json:"matchExtension,omitempty" yaml:"matchExtension"`
	TargetExtension TCPExtension   `json:"targetExtension,omitempty" yaml:"targetExtension"`
}

type RuleSet struct {
	Iface string  `json:"iface" yaml:"iface"`
	Rules []*Rule `json:"rules" yaml:"rules"`
}

type RuleFormat struct {
	IpSets   []IpSet   `json:"ipSets" yaml:"ipSets"`
	RuleSets []RuleSet `json:"ruleSets" yaml:"ruleSets"`
}

// Wall basically just a wrapper for xdpwall
type Wall struct {
	ipSets   map[string]*IpSet
	ruleSets map[string][]*Rule

	xdp *xdpwall.XdpWall
}

func NewWall() *Wall {
	w := &Wall{
		ipSets:   make(map[string]*IpSet),
		ruleSets: make(map[string][]*Rule),
	}

	w.xdp = xdpwall.NewXdpWall()

	return w
}

func (w *Wall) ListIpSet() []*IpSet {
	var entries []*IpSet
	for _, ipSet := range w.ipSets {
		entries = append(entries, ipSet)
	}
	return entries
}

func (w *Wall) LookupIpSet(setName string) (*IpSet, error) {
	_, err := w.xdp.LookupIpSet(setName)
	if err != nil {
		return nil, err
	}
	return w.ipSets[setName], nil
}

func (w *Wall) CreateIpSet(setName string) error {
	err := w.xdp.CreateIpSet(setName)
	if err != nil {
		return err
	}
	w.ipSets[setName] = &IpSet{Name: setName}
	return nil
}

func (w *Wall) AppendIp(setName string, ips ...string) error {
	err := w.xdp.AppendIp(setName, ips...)
	if err != nil {
		return err
	}
	entry := w.ipSets[setName]
	entry.Addrs = append(entry.Addrs, ips...)
	return nil
}

func (w *Wall) RemoveIp(setName string, ip string) error {
	err := w.xdp.RemoveIp(setName, ip)
	if err != nil {
		return err
	}
	entry := w.ipSets[setName]
	for i, addr := range entry.Addrs {
		if addr == ip {
			entry.Addrs = append(entry.Addrs[:i], entry.Addrs[i+1:]...)
			break
		}
	}
	return nil
}

func (w *Wall) DelIpSet(setName string) error {
	err := w.xdp.DelIpSet(setName)
	if err != nil {
		return err
	}
	delete(w.ipSets, setName)
	return nil
}

func (w *Wall) LookupRuleSet(iface string) ([]*Rule, error) {
	_, err := w.xdp.LookupRuleSet(iface)
	if err != nil {
		return nil, err
	}
	return w.ruleSets[iface], nil
}

func (w *Wall) CreateRuleSet(iface string) error {
	err := w.xdp.CreateRuleSet(iface)
	if err != nil {
		return err
	}
	w.ruleSets[iface] = make([]*Rule, 0)
	return nil
}

func (w *Wall) convertRule(rule *Rule) (xdpwall.FilterRuleItem, error) {
	var err error
	ret := xdpwall.FilterRuleItem{
		Target:   xdpTargetMap[rule.Target],
		Protocol: xdpProtocolMap[rule.Protocol],
	}

	ret.Source, ret.SourceMask, err = internal.ParseV4CIDRU32(rule.Source)
	if err != nil {
		return ret, err
	}

	ret.Destination, ret.DestinationMask, err = internal.ParseV4CIDRU32(rule.Destination)
	if err != nil {
		return ret, err
	}

	// ip set
	ret.MatchExt.Set.Id = w.xdp.GenIpSetID(rule.MatchExtension.Set.Name)
	ret.MatchExt.Set.Direction = xdpIpSetTypeMap[rule.MatchExtension.Set.Direction]

	// udp
	ret.MatchExt.Udp.Sport = uint16(rule.MatchExtension.UDP.SrcPort)
	ret.MatchExt.Udp.Dport = uint16(rule.MatchExtension.UDP.DstPort)

	// tcp
	ret.MatchExt.Tcp.Sport = uint16(rule.MatchExtension.TCP.SrcPort)
	ret.MatchExt.Tcp.Dport = uint16(rule.MatchExtension.TCP.DstPort)

	return ret, nil
}

func (w *Wall) InsertRule(iface string, pos int, rule *Rule) error {
	xdpRule, err := w.convertRule(rule)
	if err != nil {
		return err
	}
	err = w.xdp.InsertRule(iface, pos, xdpRule)
	if err != nil {
		return err
	}

	rules := w.ruleSets[iface]
	if pos == len(rules) {
		w.ruleSets[iface] = append(rules, rule)
		return nil
	}

	w.ruleSets[iface] = append(w.ruleSets[iface], nil)
	copy(w.ruleSets[iface][pos+1:], w.ruleSets[iface][pos:])
	w.ruleSets[iface][pos] = rule
	return nil
}

func (w *Wall) AppendRule(iface string, rules ...*Rule) error {
	var xdpRules []xdpwall.FilterRuleItem
	for _, r := range rules {
		xdpRule, err := w.convertRule(r)
		if err != nil {
			return err
		}
		xdpRules = append(xdpRules, xdpRule)
	}

	err := w.xdp.AppendRule(iface, xdpRules...)
	if err != nil {
		return err
	}

	w.ruleSets[iface] = append(w.ruleSets[iface], rules...)
	return nil
}

func (w *Wall) RemoveRule(iface string, pos int) error {
	err := w.xdp.RemoveRule(iface, pos)
	if err != nil {
		return err
	}
	w.ruleSets[iface] = append(w.ruleSets[iface][:pos], w.ruleSets[iface][pos+1:]...)
	return nil
}

func (w *Wall) DelRuleSet(iface string) error {
	err := w.xdp.DelRuleSet(iface)
	if err != nil {
		return err
	}
	delete(w.ruleSets, iface)
	return nil
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

	return nil
}

func (w *Wall) Run() error {
	for iface := range w.ruleSets {
		err := w.xdp.Attach(iface)
		if err != nil {
			return err
		}
	}
	return nil
}
