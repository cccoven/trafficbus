package trafficbus

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"log"
	"net"
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

type IPSet struct {
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
	Interface       string         `json:"interface"`
	Target          string         `json:"target" yaml:"target"`
	Protocol        string         `json:"protocol" yaml:"protocol"`
	Source          string         `json:"source" yaml:"source"`
	Destination     string         `json:"destination" yaml:"destination"`
	MatchExtension  MatchExtension `json:"matchExtension,omitempty" yaml:"matchExtension"`
	TargetExtension TCPExtension   `json:"targetExtension,omitempty" yaml:"targetExtension"`
}

type RuleFormat struct {
	IPSets []*IPSet `json:"ipsets" yaml:"ipsets"`
	Rules  []*Rule  `json:"rules"`
}

// Wall basically just a wrapper for xdpwall
type Wall struct {
	ipSets map[string]*IPSet
	rules  []*Rule

	xdp *xdpwall.XdpWall
}

func NewWall() *Wall {
	w := new(Wall)
	w.ipSets = make(map[string]*IPSet)

	xdpWall, err := xdpwall.NewXdpWall()
	if err != nil {
		log.Fatal(err)
	}
	w.xdp = xdpWall

	return w
}

func (w *Wall) convertIP(ip string) (xdpwall.FilterIpItem, error) {
	var err error
	var item xdpwall.FilterIpItem
	item.Addr, item.Mask, err = internal.ParseV4CIDRU32(ip)
	if err != nil {
		return item, err
	}
	item.Valid = 1

	return item, nil
}

func (w *Wall) ListIPSet() ([]*IPSet, error) {
	var entries []*IPSet
	for _, ipset := range w.ipSets {
		entries = append(entries, ipset)
	}
	return entries, nil
}

func (w *Wall) LookupIPSet(setName string) (*IPSet, error) {
	return w.ipSets[setName], nil
}

func (w *Wall) CreateIPSet(setName string) error {
	err := w.xdp.UpdateIPSet(w.str2hash(setName), xdpwall.IPSet{})
	if err != nil {
		return err
	}
	w.ipSets[setName] = &IPSet{Name: setName}
	return nil
}

func (w *Wall) ipSetSize(set xdpwall.IPSet) int {
	var size int
	for _, item := range set {
		if item.Valid == 0 {
			break
		}
		size++
	}
	return size
}

func (w *Wall) AppendIP(setName string, ips ...string) error {
	_, ok := w.ipSets[setName]
	if !ok {
		return errors.New("set does not exist")
	}
	setID := w.str2hash(setName)
	set, err := w.xdp.LookupIPSet(setID)
	if err != nil {
		return err
	}
	size := w.ipSetSize(set)

	for i, ip := range ips {
		item, err := w.convertIP(ip)
		if err != nil {
			return err
		}
		set[i+size] = item
	}

	err = w.xdp.UpdateIPSet(setID, set)
	if err != nil {
		return err
	}

	w.ipSets[setName].Addrs = append(w.ipSets[setName].Addrs, ips...)
	return nil
}

func (w *Wall) RemoveIP(setName string, ip string) error {
	ipSet, ok := w.ipSets[setName]
	if !ok {
		return errors.New("set does not exist")
	}

	uip, umask, err := internal.ParseV4CIDRU32(ip)
	if err != nil {
		return err
	}

	setID := w.str2hash(setName)
	set, err := w.xdp.LookupIPSet(setID)
	if err != nil {
		return err
	}

	// delete ip in map
	for i, item := range set {
		if item.Addr == uip && item.Mask == umask {
			copy(set[i:], set[i+1:])
			break
		}
	}
	err = w.xdp.UpdateIPSet(setID, set)
	if err != nil {
		return err
	}

	for i, addr := range ipSet.Addrs {
		if addr == ip {
			ipSet.Addrs = append(ipSet.Addrs[:i], ipSet.Addrs[i+1:]...)
			break
		}
	}

	return nil
}

// str2hash use uint32 hash as ipset name
func (w *Wall) str2hash(s string) uint32 {
	hasher := fnv.New32()
	hasher.Write([]byte(s))
	return hasher.Sum32()
}

func (w *Wall) convertRule(rule *Rule) (xdpwall.FilterRule, error) {
	var ret xdpwall.FilterRule
	var err error

	iface, err := net.InterfaceByName(rule.Interface)
	if err != nil {
		return ret, err
	}

	ret.Interface = int32(iface.Index)
	ret.Target = xdpTargetMap[rule.Target]
	ret.Protocol = xdpProtocolMap[rule.Protocol]

	ret.Source, ret.SourceMask, err = internal.ParseV4CIDRU32(rule.Source)
	if err != nil {
		return ret, err
	}

	ret.Destination, ret.DestinationMask, err = internal.ParseV4CIDRU32(rule.Destination)
	if err != nil {
		return ret, err
	}

	// ip set
	ret.MatchExt.Set.Id = w.str2hash(rule.MatchExtension.Set.Name)
	ret.MatchExt.Set.Direction = xdpIpSetTypeMap[rule.MatchExtension.Set.Direction]

	// udp
	ret.MatchExt.Udp.Sport = uint16(rule.MatchExtension.UDP.SrcPort)
	ret.MatchExt.Udp.Dport = uint16(rule.MatchExtension.UDP.DstPort)

	// tcp
	ret.MatchExt.Tcp.Sport = uint16(rule.MatchExtension.TCP.SrcPort)
	ret.MatchExt.Tcp.Dport = uint16(rule.MatchExtension.TCP.DstPort)

	return ret, nil
}

func (w *Wall) ListRule() ([]*Rule, error) {
	return w.rules, nil
}

func (w *Wall) InsertRule(pos int, rule *Rule) error {
	xdpRule, err := w.convertRule(rule)
	if err != nil {
		return err
	}
	err = w.xdp.UpdateRule(uint32(pos), xdpRule)
	if err != nil {
		return err
	}

	if pos == len(w.rules) {
		w.rules = append(w.rules, rule)
		return nil
	}

	w.rules = append(w.rules, nil)
	copy(w.rules[pos+1:], w.rules[pos:])
	w.rules[pos] = rule
	return nil
}

func (w *Wall) AppendRule(rules ...*Rule) error {
	var keys []uint32
	var values []xdpwall.FilterRule
	l := len(w.rules)

	for i, r := range rules {
		xdpRule, err := w.convertRule(r)
		if err != nil {
			return err
		}
		keys = append(keys, uint32(i+l))
		values = append(values, xdpRule)
	}

	_, err := w.xdp.UpdateRules(keys, values)
	if err != nil {
		return err
	}

	w.rules = append(w.rules, rules...)
	return nil
}

func (w *Wall) RemoveRule(pos int) error {
	err := w.xdp.UpdateRule(uint32(pos), xdpwall.FilterRule{})
	if err != nil {
		return err
	}
	w.rules = append(w.rules[:pos], w.rules[pos+1:]...)
	return nil
}

func (w *Wall) LoadFromJson(f string) error {
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}

	var ruleFormat RuleFormat
	err = json.Unmarshal(data, &ruleFormat)
	if err != nil {
		return err
	}

	for _, ipset := range ruleFormat.IPSets {
		err = w.CreateIPSet(ipset.Name)
		if err != nil {
			return err
		}
		err = w.AppendIP(ipset.Name, ipset.Addrs...)
		if err != nil {
			return err
		}
	}

	err = w.AppendRule(ruleFormat.Rules...)
	if err != nil {
		return err
	}

	return nil
}

func (w *Wall) LoadFromYaml(f string) error {

	return nil
}

func (w *Wall) Run() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		w.xdp.Attach(iface.Index)
	}
	return nil
}

func (w *Wall) RecvMatchLogs() error {
	for {
		mlog, err := w.xdp.ReadMatchLog()
		if err != nil {
			return err
		}

		log.Printf("matchIndex: %d, bytes: %d", mlog.RuleIndex, mlog.Bytes)
	}
}
