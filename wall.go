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
	"time"

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

	xdpTCPFlagMap = map[string]xdpwall.FilterTcpFlag{
		"SYN": xdpwall.FilterTcpFlagSYN,
		"ACK": xdpwall.FilterTcpFlagACK,
		"PSH": xdpwall.FilterTcpFlagPSH,
		"URG": xdpwall.FilterTcpFlagURG,
		"FIN": xdpwall.FilterTcpFlagFIN,
		"RST": xdpwall.FilterTcpFlagRST,
	}

	tokenBucketLimit = map[string]time.Duration{}
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
	Src int `json:"src" yaml:"src"`
	Dst int `json:"dst" yaml:"dst"`
}

type TCPFlags struct {
	Mask string `json:"mask" yaml:"mask"`
	Comp string `json:"comp" yaml:"comp"`
}

type TCPExtension struct {
	Src   int       `json:"src" yaml:"src"`
	Dst   int       `json:"dst" yaml:"dst"`
	Flags *TCPFlags `json:"flags" yaml:"flags"`
	Syn   bool      `json:"syn" yaml:"syn"`
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
	Limit     string              `json:"limit" yaml:"limit"`
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

// str2hash use uint32 hash as ipset name
func str2hash(s string) uint32 {
	if s == "" {
		return 0
	}
	hasher := fnv.New32()
	hasher.Write([]byte(s))
	return hasher.Sum32()
}

type RuleParser struct{}

func NewRuleParser() *RuleParser {
	return &RuleParser{}
}

func (p *RuleParser) ParseIP(ip string) (xdpwall.FilterIpItem, error) {
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

func (p *RuleParser) ParseIPSet(dst *xdpwall.FilterSetExt, ori *SetExtension) {
	if ori == nil {
		return
	}
	dst.Enable = 1
	dst.Id = str2hash(ori.Name)
	dst.Direction = xdpIpSetTypeMap[ori.Direction]
}

func (p *RuleParser) ParseUDP(dst *xdpwall.FilterUdpExt, ori *UDPExtension) {
	if ori == nil {
		return
	}
	dst.Enable = 1
	dst.Src = uint16(ori.Src)
	dst.Dst = uint16(ori.Src)
}

func (p *RuleParser) parseTCPFlags(flags string) int32 {
	if flags == "" {
		return 0
	}
	var flagBits int32
	for _, f := range strings.Split(flags, ",") {
		bit, ok := xdpTCPFlagMap[f]
		if !ok {
			continue
		}
		flagBits |= int32(bit)
	}
	return flagBits
}

func (p *RuleParser) ParseTCP(dst *xdpwall.FilterTcpExt, ori *TCPExtension) {
	if ori == nil {
		return
	}
	dst.Enable = 1
	dst.Src = uint16(ori.Src)
	dst.Dst = uint16(ori.Dst)
	if ori.Syn {
		ori.Flags = &TCPFlags{
			Mask: "SYN,ACK,PSH,URG,FIN,RST",
			Comp: "SYN",
		}
	}
	if ori.Flags != nil {
		dst.Flags.Mask = p.parseTCPFlags(ori.Flags.Mask)
		dst.Flags.Comp = p.parseTCPFlags(ori.Flags.Comp)
	}
}

func (p *RuleParser) parseMultiPort(pairs *xdpwall.FilterMultiPortPairs, ports string) error {
	if ports == "" {
		return nil
	}

	pairs.Enable = 1
	for i, p := range strings.Split(ports, ",") {
		var minPort, maxPort uint16
		if strings.Contains(p, ":") {
			portRange := strings.Split(p, ":")
			minp, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return err
			}
			maxp, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return err
			}
			minPort = uint16(minp)
			maxPort = uint16(maxp)
		} else {
			minp, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return err
			}
			minPort = uint16(minp)
		}
		pairs.Data[i].Port = minPort
		pairs.Data[i].Max = maxPort
	}

	return nil
}

func (p *RuleParser) ParseMultiPort(dst *xdpwall.FilterMultiPortExt, ori *MultiPortExtension) error {
	if ori == nil {
		return nil
	}
	err := p.parseMultiPort(&dst.Src, ori.Src)
	if err != nil {
		return err
	}
	err = p.parseMultiPort(&dst.Dst, ori.Dst)
	if err != nil {
		return err
	}
	return nil
}

func (p *RuleParser) ParseLimit(s string) xdpwall.FilterBucket {
	ret := xdpwall.FilterBucket{
		StartMoment:     1,
		Capacity:        0,
		Quantum:         0,
		FillInterval:    0,
		AvailableTokens: 0,
		LatestTick:      0,
	}

	return ret
}

func (p *RuleParser) ParseRule(rule *Rule) (xdpwall.FilterRule, error) {
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

	// parse extensions
	ext := rule.MatchExtension
	if ext != nil {
		ret.MatchExt.Enable = 1
		// ip set
		p.ParseIPSet(&ret.MatchExt.Set, ext.Set)
		// udp
		p.ParseUDP(&ret.MatchExt.Udp, ext.UDP)
		// tcp
		p.ParseTCP(&ret.MatchExt.Tcp, ext.TCP)
		// multi port
		err = p.ParseMultiPort(&ret.MatchExt.MultiPort, ext.MultiPort)
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}

// Wall basically just a wrapper for xdpwall
type Wall struct {
	ipSets map[string]*IPSet
	rules  []*Rule

	parser *RuleParser
	xdp    *xdpwall.XdpWall
}

func NewWall() *Wall {
	w := new(Wall)
	w.ipSets = make(map[string]*IPSet)

	xdpWall, err := xdpwall.NewXdpWall()
	if err != nil {
		log.Fatal(err)
	}
	w.xdp = xdpWall

	w.parser = NewRuleParser()

	return w
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
	err := w.xdp.UpdateIPSet(str2hash(setName), xdpwall.IPSet{})
	if err != nil {
		return err
	}
	w.ipSets[setName] = &IPSet{Name: setName}
	return nil
}

func (w *Wall) AppendIP(setName string, ips ...string) error {
	_, ok := w.ipSets[setName]
	if !ok {
		return errors.New("set does not exist")
	}
	setID := str2hash(setName)
	set, err := w.xdp.LookupIPSet(setID)
	if err != nil {
		return err
	}
	size := set.EnabledSize()

	for i, ip := range ips {
		item, err := w.parser.ParseIP(ip)
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

	setID := str2hash(setName)
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

func (w *Wall) ListRule() ([]*Rule, error) {
	return w.rules, nil
}

func (w *Wall) InsertRule(pos int, rule *Rule) error {
	rules := w.xdp.ListRules()
	size := len(rules)

	if pos > size {
		return fmt.Errorf("pos %d out of range", pos)
	}

	xdpRule, err := w.parser.ParseRule(rule)
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
		xdpRule, err := w.parser.ParseRule(r)
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
