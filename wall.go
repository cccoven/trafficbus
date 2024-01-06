package trafficbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cccoven/trafficbus/internal"
	"github.com/cccoven/trafficbus/internal/ebpf/xdpwall"
	"github.com/spf13/viper"
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

type MultiPortExtension struct {
	Src string `json:"src" yaml:"src"`
	Dst string `json:"dst" yaml:"dst"`
}

type MatchExtension struct {
	Set       *SetExtension       `json:"set,omitempty" yaml:"set"`
	UDP       *UDPExtension       `json:"udp,omitempty" yaml:"udp"`
	TCP       *TCPExtension       `json:"tcp,omitempty" yaml:"tcp"`
	MultiPort *MultiPortExtension `json:"multiPort" yaml:"multiPort"`
}

type TargetExtension struct{}

type Rule struct {
	Packets int
	Bytes   uint64

	Interface       string           `json:"interface"`
	Target          string           `json:"target" yaml:"target"`
	Protocol        string           `json:"protocol" yaml:"protocol"`
	Source          string           `json:"source" yaml:"source"`
	Destination     string           `json:"destination" yaml:"destination"`
	MatchExtension  *MatchExtension  `json:"matchExtension,omitempty" yaml:"matchExtension"`
	TargetExtension *TargetExtension `json:"targetExtension,omitempty" yaml:"targetExtension"`
}

type RuleFormat struct {
	IPSets []*IPSet `json:"sets" yaml:"ipSets"`
	Rules  []*Rule  `json:"rules" yaml:"rules"`
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
	item := xdpwall.FilterIpItem{
		Enable: 1,
	}
	item.Addr, item.Mask, err = internal.ParseV4CIDRU32(ip)
	if err != nil {
		return item, err
	}

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
	err := w.xdp.UpdateIPSet(w.genIPSetID(setName), xdpwall.IPSet{})
	if err != nil {
		return err
	}
	w.ipSets[setName] = &IPSet{Name: setName}
	return nil
}

func (w *Wall) enabledIPSize(set xdpwall.IPSet) int {
	var size int
	for _, item := range set {
		if item.Enable == 0 {
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
	setID := w.genIPSetID(setName)
	set, err := w.xdp.LookupIPSet(setID)
	if err != nil {
		return err
	}
	size := w.enabledIPSize(set)

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

	setID := w.genIPSetID(setName)
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

// genIPSetID use uint32 hash as ipset name
func (w *Wall) genIPSetID(s string) uint32 {
	if s == "" {
		return 0
	}
	hasher := fnv.New32()
	hasher.Write([]byte(s))
	return hasher.Sum32()
}

func (w *Wall) parseMultiPort(raw string) (port uint16, maxPort uint16, err error) {
	var p, m uint64
	if strings.Contains(raw, ":") {
		portRange := strings.Split(raw, ":")
		p, err = strconv.ParseUint(portRange[0], 10, 16)
		if err != nil {
			return
		}
		m, err = strconv.ParseUint(portRange[1], 10, 16)
		if err != nil {
			return
		}
	} else {
		p, err = strconv.ParseUint(raw, 10, 16)
		if err != nil {
			return
		}
	}

	port = uint16(p)
	maxPort = uint16(m)
	return
}

func (w *Wall) parseRule(rule *Rule) (xdpwall.FilterRule, error) {
	var err error
	ret := xdpwall.FilterRule{
		Enable:    1,
		Interface: 0,
		Target:    xdpTargetMap[rule.Target],
		Protocol:  xdpProtocolMap[rule.Protocol],
	}

	iface, _ := net.InterfaceByName(rule.Interface)
	if iface != nil {
		ret.Interface = int32(iface.Index)
	}

	ret.Source, ret.SourceMask, err = internal.ParseV4CIDRU32(rule.Source)
	if err != nil {
		return ret, err
	}

	ret.Destination, ret.DestinationMask, err = internal.ParseV4CIDRU32(rule.Destination)
	if err != nil {
		return ret, err
	}

	ext := rule.MatchExtension
	if ext != nil {
		ret.MatchExt.Enable = 1

		// ip set
		if ext.Set != nil {
			ret.MatchExt.Set.Enable = 1
			ret.MatchExt.Set.Id = w.genIPSetID(ext.Set.Name)
			ret.MatchExt.Set.Direction = xdpIpSetTypeMap[ext.Set.Direction]
		}

		// udp
		if ext.UDP != nil {
			ret.MatchExt.Udp.Enable = 1
			ret.MatchExt.Udp.Sport = uint16(ext.UDP.SrcPort)
			ret.MatchExt.Udp.Dport = uint16(ext.UDP.DstPort)
		}

		// tcp
		if ext.TCP != nil {
			ret.MatchExt.Tcp.Enable = 1
			ret.MatchExt.Tcp.Sport = uint16(ext.TCP.SrcPort)
			ret.MatchExt.Tcp.Dport = uint16(ext.TCP.DstPort)
		}

		if ext.MultiPort != nil {
			// multi ports
			if ext.MultiPort.Src != "" {
				ret.MatchExt.MultiPort.Src.Enable = 1
				ports := strings.Split(ext.MultiPort.Src, ",")
				for i, p := range ports {
					port, maxPort, err := w.parseMultiPort(p)
					if err != nil {
						return ret, err
					}
					ret.MatchExt.MultiPort.Src.Data[i].Port = port
					ret.MatchExt.MultiPort.Src.Data[i].Max = maxPort
				}
			}
			if ext.MultiPort.Dst != "" {
				ret.MatchExt.MultiPort.Dst.Enable = 1
				ports := strings.Split(ext.MultiPort.Dst, ",")
				for i, p := range ports {
					port, maxPort, err := w.parseMultiPort(p)
					if err != nil {
						return ret, err
					}
					ret.MatchExt.MultiPort.Dst.Data[i].Port = port
					ret.MatchExt.MultiPort.Dst.Data[i].Max = maxPort
				}
			}
		}
	}

	return ret, nil
}

func (w *Wall) ListRule() ([]*Rule, error) {
	return w.rules, nil
}

func (w *Wall) InsertRule(pos int, rule *Rule) error {
	rules := w.xdp.ListRules()
	size := len(rules)

	if pos > size {
		return fmt.Errorf("pos %d out of range", pos)
	}

	xdpRule, err := w.parseRule(rule)
	if err != nil {
		return err
	}

	if pos == size {
		err = w.xdp.UpdateRule(uint32(pos), xdpRule)
		if err != nil {
			return err
		}
		w.rules = append(w.rules, rule)
		return nil
	}

	rules = append(rules, xdpwall.FilterRule{})
	copy(rules[pos+1:], rules[pos:])
	rules[pos] = xdpRule
	size++

	var keys []uint32
	var values []xdpwall.FilterRule
	for i := pos; i < size; i++ {
		keys = append(keys, uint32(i))
		values = append(values, rules[i])
	}
	_, err = w.xdp.UpdateRules(keys, values)
	if err != nil {
		return err
	}

	w.rules = append(w.rules, nil)
	copy(w.rules[pos+1:], w.rules[pos:])
	w.rules[pos] = rule
	return nil
}

func (w *Wall) AppendRule(rules ...*Rule) error {
	if len(rules) == 0 {
		return nil
	}

	var keys []uint32
	var values []xdpwall.FilterRule

	size := len(w.xdp.ListRules())
	for i, r := range rules {
		xdpRule, err := w.parseRule(r)
		if err != nil {
			return err
		}
		keys = append(keys, uint32(i+size))
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
	rules := w.xdp.ListRules()
	size := len(rules)

	if pos > size {
		return fmt.Errorf("pos %d out of range", pos)
	}

	if pos == size {
		err := w.xdp.UpdateRule(uint32(pos), xdpwall.FilterRule{})
		if err != nil {
			return err
		}
	} else {
		copy(rules[pos:], rules[pos+1:])
		size--

		var keys []uint32
		var values []xdpwall.FilterRule
		for i := pos; i < size; i++ {
			keys = append(keys, uint32(i))
			values = append(values, rules[i])
		}
		_, err := w.xdp.UpdateRules(keys, values)
		if err != nil {
			return err
		}
	}

	w.rules = append(w.rules[:pos], w.rules[pos+1:]...)
	return nil
}

func (w *Wall) loadFormat(f *RuleFormat) error {
	for _, ipset := range f.IPSets {
		err := w.CreateIPSet(ipset.Name)
		if err != nil {
			return err
		}
		err = w.AppendIP(ipset.Name, ipset.Addrs...)
		if err != nil {
			return err
		}
	}

	err := w.AppendRule(f.Rules...)
	if err != nil {
		return err
	}

	return nil
}

func (w *Wall) LoadFromJson(f string) error {
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}

	var ruleFormat *RuleFormat
	err = json.Unmarshal(data, &ruleFormat)
	if err != nil {
		return err
	}

	return w.loadFormat(ruleFormat)
}

func (w *Wall) LoadFromYaml(f string) error {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigFile(f)
	err := v.ReadInConfig()
	if err != nil {
		return err
	}

	var ruleFormat *RuleFormat
	err = v.Unmarshal(&ruleFormat)
	if err != nil {
		return err
	}

	return w.loadFormat(ruleFormat)
}

func (w *Wall) Run() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		w.xdp.Attach(iface.Index)
	}

	w.listenMatchEvent()

	return err
}

func (w *Wall) Stop() error {
	return w.xdp.Stop()
}

func (w *Wall) listenMatchEvent() {
	for {
		evt, err := w.xdp.ReadMatchEvent()
		if err != nil {
			log.Printf("failed to read match event: %s", err.Error())
			continue
		}

		rule := w.rules[evt.RuleIndex]
		if rule == nil {
			continue
		}

		rule.Packets++
		rule.Bytes += evt.Bytes

		log.Printf("rule.index: %d, rule.pkts: %d, rule.bytes: %d", evt.RuleIndex, rule.Packets, rule.Bytes)
	}
}
