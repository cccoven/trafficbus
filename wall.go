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

	xdpTCPFlagMap = map[string]xdpwall.FilterTcpFlag{
		"SYN": xdpwall.FilterTcpFlagSYN,
		"ACK": xdpwall.FilterTcpFlagACK,
		"PSH": xdpwall.FilterTcpFlagPSH,
		"URG": xdpwall.FilterTcpFlagURG,
		"FIN": xdpwall.FilterTcpFlagFIN,
		"RST": xdpwall.FilterTcpFlagRST,
	}

	tokenBucketLimit = map[string]uint64{
		"second": 1 * 1000000000, // nanosec
		"minute": (1 * 60) * 1000000000,
		"hour":   (1 * 60 * 60) * 1000000000,
		"day":    (1 * 60 * 60 * 24) * 1000000000,
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

type RuleParser struct {
	xdp *xdpwall.XdpWall
}

func NewRuleParser(xdp *xdpwall.XdpWall) *RuleParser {
	return &RuleParser{
		xdp: xdp,
	}
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

func (p *RuleParser) ParseTCPFlags(flags string) int32 {
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
		dst.Flags.Mask = p.ParseTCPFlags(ori.Flags.Mask)
		dst.Flags.Comp = p.ParseTCPFlags(ori.Flags.Comp)
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

func (p *RuleParser) ParseLimit(s string) (*xdpwall.FilterBucket, error) {
	rate := strings.Split(s, "/")
	ret := &xdpwall.FilterBucket{}

	capacity, err := strconv.ParseUint(rate[0], 10, 64)
	if err != nil {
		return nil, err
	}

	seconds, ok := tokenBucketLimit[rate[1]]
	if !ok {
		return nil, fmt.Errorf("unspported rate: %s", rate[1])
	}

	ret.StartMoment = 1
	ret.Capacity = capacity
	ret.Quantum = capacity
	ret.FillInterval = seconds

	return ret, nil
}

func (p *RuleParser) ParseMatchExtension(ext *MatchExtension) (*xdpwall.FilterMatchExt, error) {
	ret := &xdpwall.FilterMatchExt{}
	// ip set
	p.ParseIPSet(&ret.Set, ext.Set)
	// udp
	p.ParseUDP(&ret.Udp, ext.UDP)
	// tcp
	p.ParseTCP(&ret.Tcp, ext.TCP)
	// multi port
	err := p.ParseMultiPort(&ret.MultiPort, ext.MultiPort)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (p *RuleParser) ParseRule(rule *Rule) (*xdpwall.FilterRule, error) {
	var err error
	ret := &xdpwall.FilterRule{
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
		return nil, err
	}
	ret.Destination, ret.DestinationMask, err = internal.ParseV4CIDRU32(rule.Destination)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (p *RuleParser) SyncRule(key uint32, value *Rule) error {
	var (
		xdpRule     *xdpwall.FilterRule
		xdpMatchExt *xdpwall.FilterMatchExt
		xdpBucket   *xdpwall.FilterBucket
		err         error
	)

	xdpRule, err = p.ParseRule(value)
	if err != nil {
		return err
	}

	if value.MatchExtension != nil {
		xdpMatchExt, err = p.ParseMatchExtension(value.MatchExtension)
		if err != nil {
			return err
		}

		if value.MatchExtension.Limit != "" {
			// create a token bucket for this rule
			xdpBucket, err = p.ParseLimit(value.MatchExtension.Limit)
			if err != nil {
				return err
			}
		}
	}

	if xdpRule != nil {
		if err = p.xdp.UpdateRule(key, xdpRule); err != nil {
			return err
		}
	}
	if xdpMatchExt != nil {
		if err = p.xdp.UpdateMatchExt(key, xdpMatchExt); err != nil {
			return err
		}
	}
	if xdpBucket != nil {
		if err = p.xdp.UpdateBucket(key, xdpBucket); err != nil {
			return err
		}
	}

	return nil
}

func (p *RuleParser) DeleteRule(key uint32) error {
	err := p.xdp.UpdateRule(key, nil)
	if err != nil {
		return err
	}
	err = p.xdp.DeleteMatchExt(key)
	if err != nil {
		return err
	}
	err = p.xdp.DeleteBucket(key)
	if err != nil {
		return err
	}
	return nil
}

// func (p *RuleParser) SyncRules(keys []uint32, rules []*Rule) error {
// 	var values []xdpwall.FilterRule

// 	for _, rule := range rules {
// 		xr, err := p.ParseRule(rule)
// 		if err != nil {
// 			return err
// 		}
// 		values = append(values, xr)
// 	}
// }

// func (p *RuleParser) SyncRules(rules []*Rule) error {
// 	var xdpRulekeys []uint32
// 	var xdpRules []xdpwall.FilterRule
// 	var xdpRuleExtensionKeys []uint32
// 	var xdpRuleExtensions []xdpwall.FilterMatchExt
// 	var xdpBucketKeys []uint32
// 	var xdpBuckets []xdpwall.FilterBucket
// 	size := len(p.xdp.ListRules())

// 	for i, rule := range rules {
// 		xr, err := p.ParseRule(rule)
// 		if err != nil {
// 			return err
// 		}

// 		key := uint32(i + size)
// 		xdpRules = append(xdpRules, xr)
// 		xdpRulekeys = append(xdpRulekeys, key)

// 		if rule.MatchExtension != nil {
// 			ext, err := p.ParseMatchExtension(rule.MatchExtension)
// 			if err != nil {
// 				return err
// 			}
// 			xdpRuleExtensions = append(xdpRuleExtensions, ext)
// 			xdpRuleExtensionKeys = append(xdpRuleExtensionKeys, key)

// 			if rule.MatchExtension.Limit != "" {
// 				bucket, err := p.ParseLimit(rule.MatchExtension.Limit)
// 				if err != nil {
// 					return err
// 				}

// 				xdpBuckets = append(xdpBuckets, bucket)
// 				xdpBucketKeys = append(xdpBucketKeys, key)
// 			}
// 		}
// 	}

// 	if len(xdpBucketKeys) > 0 {
// 		_, err := p.xdp.UpdateRules(xdpRulekeys, xdpRules)
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	if len(xdpRuleExtensionKeys) > 0 {
// 		_, err := p.xdp.UpdateMatchExts(xdpRuleExtensionKeys, xdpRuleExtensions)
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	if len(xdpBucketKeys) > 0 {
// 		_, err := p.xdp.UpdateBuckets(xdpBucketKeys, xdpBuckets)
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

type WallOptions struct {
	RuleFile string
}

// Wall basically just a wrapper for xdpwall
type Wall struct {
	ipSets map[string]*IPSet
	rules  []*Rule

	parser *RuleParser
	xdp    *xdpwall.XdpWall
}

func NewWall(options *WallOptions) *Wall {
	w := new(Wall)
	w.ipSets = make(map[string]*IPSet)

	xdpWall, err := xdpwall.NewXdpWall()
	if err != nil {
		log.Fatal(err)
	}
	w.xdp = xdpWall

	w.parser = NewRuleParser(xdpWall)

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

	err := w.parser.SyncRule(uint32(pos), rule)
	if err != nil {
		return err
	}

	if pos == size {
		w.rules = append(w.rules, rule)
	} else {
		for i := pos; i < len(w.rules); i++ {
			err = w.parser.SyncRule(uint32(i+1), w.rules[i])
			if err != nil {
				return err
			}
		}
		w.rules = append(w.rules, nil)
		copy(w.rules[pos+1:], w.rules[pos:])
		w.rules[pos] = rule
	}

	// if pos == size {
	// 	// append
	// 	err := w.parser.SyncRule(uint32(pos), rule)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	w.rules = append(w.rules, rule)
	// } else {
	// 	size++
	// 	for i := pos; i < size; i++ {

	// 	}
	// }

	// rules = append(rules, xdpwall.FilterRule{})
	// copy(rules[pos+1:], rules[pos:])
	// rules[pos] = xdpRule
	// size++

	// var keys []uint32
	// var values []xdpwall.FilterRule
	// for i := pos; i < size; i++ {
	// 	keys = append(keys, uint32(i))
	// 	values = append(values, rules[i])
	// }
	// _, err = w.xdp.UpdateRules(keys, values)
	// if err != nil {
	// 	return err
	// }

	// w.rules = append(w.rules, nil)
	// copy(w.rules[pos+1:], w.rules[pos:])
	// w.rules[pos] = rule
	return nil
}

func (w *Wall) AppendRule(rules ...*Rule) error {
	if len(rules) == 0 {
		return nil
	}

	// var keys []uint32
	// var values []xdpwall.FilterRule

	size := len(w.xdp.ListRules())
	for i, r := range rules {
		err := w.parser.SyncRule(uint32(i+size), r)
		if err != nil {
			return err
		}

		// xdpRule, err := w.parser.ParseRule(r)
		// if err != nil {
		// 	return err
		// }
		// key := uint32(i + size)
		// keys = append(keys, key)
		// values = append(values, *xdpRule)

		// if r.MatchExtension != nil {
		// 	ext, err := w.parser.ParseMatchExtension(r.MatchExtension)
		// 	if err != nil {
		// 		return err
		// 	}
		// 	err = w.xdp.UpdateMatchExt(key, ext)
		// 	if err != nil {
		// 		return err
		// 	}

		// 	if r.MatchExtension.Limit != "" {
		// 		// create a token bucket for this rule
		// 		bucket, err := w.parser.ParseLimit(r.MatchExtension.Limit)
		// 		if err != nil {
		// 			return err
		// 		}
		// 		err = w.xdp.UpdateBucket(key, bucket)
		// 		if err != nil {
		// 			return err
		// 		}
		// 	}
		// }
	}

	// _, err := w.xdp.UpdateRules(keys, values)
	// if err != nil {
	// 	return err
	// }

	w.rules = append(w.rules, rules...)
	return nil
}

func (w *Wall) RemoveRule(pos int) error {
	rules := w.xdp.ListRules()
	size := len(rules)

	if pos > size {
		return fmt.Errorf("pos %d out of range", pos)
	}

	err := w.parser.DeleteRule(uint32(pos))
	if err != nil {
		return err
	}

	if pos == size {
		// err := w.parser.DeleteRule(uint32(pos))
		// if err != nil {
		// 	return err
		// }
		w.rules = append(w.rules[:pos], w.rules[pos+1:]...)
	} else {
		for i := pos; i < size; i++ {
			err := w.parser.SyncRule(uint32(i+1), w.rules[i])
			if err != nil {
				return err
			}
		}
		w.rules = append(w.rules[:pos], w.rules[pos+1:]...)
		// copy(rules[pos:], rules[pos+1:])
		// size--
		// var keys []uint32
		// var values []xdpwall.FilterRule
		// for i := pos; i < size; i++ {
		// 	keys = append(keys, uint32(i))
		// 	values = append(values, rules[i])
		// }
		// _, err := w.xdp.UpdateRules(keys, values)
		// if err != nil {
		// 	return err
		// }
	}

	// w.rules = append(w.rules[:pos], w.rules[pos+1:]...)
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
		if err := w.xdp.Attach(iface.Index); err != nil {
			return err
		}
		log.Printf("attached firewall to iface %s", iface.Name)
	}

	go w.receiveEvents()
	return nil
}

func (w *Wall) Stop() error {
	return w.xdp.Stop()
}

func (w *Wall) receiveEvents() {
	for {
		select {
		case me, ok := <-w.xdp.ReadMatchEvent():
			if !ok {
				return
			}
			rule := w.rules[me.RuleIndex]
			if rule == nil {
				continue
			}
			rule.Packets++
			rule.Bytes += me.Bytes
			log.Printf("rule.index: %d, rule.pkts: %d, rule.bytes: %d", me.RuleIndex, rule.Packets, rule.Bytes)
		}
	}
}
