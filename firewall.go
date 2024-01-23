package trafficbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cccoven/trafficbus/internal/ipaddr"
	"github.com/cccoven/trafficbus/internal/ebpf/xdpwall"
	"github.com/spf13/viper"
)

const SockFile = "/var/run/tbus"

type RuleOperation int

const (
	OpAppend RuleOperation = iota + 1
	OpInsert
	OpDelete
	OpList
	OpClear
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
	Packets int    `json:"packets"`
	Bytes   uint64 `json:"bytes"`

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

type ruleConverter struct{}

func newRuleConverter() *ruleConverter {
	return &ruleConverter{}
}

func (c *ruleConverter) ParseIPItem(ip string) (xdpwall.FilterIpItem, error) {
	var err error
	item := xdpwall.FilterIpItem{
		Enable: 1,
	}
	item.Addr, item.Mask, err = ipaddr.ParseV4CIDRU32(ip)
	if err != nil {
		return item, err
	}
	return item, nil
}

func (c *ruleConverter) ParseIPSet(ori *SetExtension) (xdpwall.FilterSetExt, error) {
	ext := xdpwall.FilterSetExt{}
	ext.Enable = 1
	ext.Id = str2hash(ori.Name)
	ext.Direction = xdpIpSetTypeMap[ori.Direction]
	return ext, nil
}

func (c *ruleConverter) ParseUDP(ori *UDPExtension) (xdpwall.FilterUdpExt, error) {
	ext := xdpwall.FilterUdpExt{}
	ext.Enable = 1
	ext.Src = uint16(ori.Src)
	ext.Dst = uint16(ori.Src)
	return ext, nil
}

func (c *ruleConverter) tcpFlagsBitMask(flags string) int32 {
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

func (c *ruleConverter) ParseTCP(ori *TCPExtension) (xdpwall.FilterTcpExt, error) {
	ext := xdpwall.FilterTcpExt{}
	ext.Enable = 1
	ext.Src = uint16(ori.Src)
	ext.Dst = uint16(ori.Dst)
	if ori.Syn {
		ori.Flags = &TCPFlags{
			Mask: "SYN,ACK,PSH,URG,FIN,RST",
			Comp: "SYN",
		}
	}
	if ori.Flags != nil {
		ext.Flags.Mask = c.tcpFlagsBitMask(ori.Flags.Mask)
		ext.Flags.Comp = c.tcpFlagsBitMask(ori.Flags.Comp)
	}
	return ext, nil
}

func (c *ruleConverter) parseMultiPort(ports string) (xdpwall.FilterMultiPortPairs, error) {
	pairs := xdpwall.FilterMultiPortPairs{
		Enable: 1,
	}

	for i, p := range strings.Split(ports, ",") {
		var minPort, maxPort uint16
		if strings.Contains(p, ":") {
			portRange := strings.Split(p, ":")
			minp, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return xdpwall.FilterMultiPortPairs{}, err
			}
			maxp, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return xdpwall.FilterMultiPortPairs{}, err
			}
			minPort = uint16(minp)
			maxPort = uint16(maxp)
		} else {
			minp, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return xdpwall.FilterMultiPortPairs{}, err
			}
			minPort = uint16(minp)
		}
		pairs.Data[i].Port = minPort
		pairs.Data[i].Max = maxPort
	}

	return pairs, nil
}

func (c *ruleConverter) ParseMultiPort(ori *MultiPortExtension) (xdpwall.FilterMultiPortExt, error) {
	var err error
	ext := xdpwall.FilterMultiPortExt{}
	if ori.Src != "" {
		ext.Src, err = c.parseMultiPort(ori.Src)
		if err != nil {
			return xdpwall.FilterMultiPortExt{}, err
		}
	}
	if ori.Dst != "" {
		ext.Dst, err = c.parseMultiPort(ori.Dst)
		if err != nil {
			return xdpwall.FilterMultiPortExt{}, err
		}
	}
	return ext, nil
}

func (c *ruleConverter) ParseLimit(s string) (*xdpwall.FilterBucket, error) {
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

func (c *ruleConverter) ParseMatchExtension(ext *MatchExtension) (*xdpwall.RuleMatchExtension, error) {
	var err error
	ret := &xdpwall.RuleMatchExtension{}
	// ip set
	if ext.Set != nil {
		ret.Set, err = c.ParseIPSet(ext.Set)
		if err != nil {
			return nil, err
		}
	}
	// udp
	if ext.UDP != nil {
		ret.Udp, err = c.ParseUDP(ext.UDP)
		if err != nil {
			return nil, err
		}
	}
	// tcp
	if ext.TCP != nil {
		ret.Tcp, err = c.ParseTCP(ext.TCP)
		if err != nil {
			return nil, err
		}
	}
	// multi port
	if ext.MultiPort != nil {
		ret.MultiPort, err = c.ParseMultiPort(ext.MultiPort)
		if err != nil {
			return nil, err
		}
	}
	// limiter
	if ext.Limit != "" {
		ret.Limiter, err = c.ParseLimit(ext.Limit)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (c *ruleConverter) ParseRule(r *Rule) (*xdpwall.Rule, error) {
	var err error
	rule := &xdpwall.Rule{}
	rule.Enable = 1
	iface, _ := net.InterfaceByName(r.Interface)
	if iface != nil {
		rule.Interface = int32(iface.Index)
	}
	rule.Target = xdpTargetMap[r.Target]
	rule.Protocol = xdpProtocolMap[r.Protocol]
	rule.Source, rule.SourceMask, err = ipaddr.ParseV4CIDRU32(r.Source)
	if err != nil {
		return nil, err
	}
	rule.Destination, rule.DestinationMask, err = ipaddr.ParseV4CIDRU32(r.Destination)
	if err != nil {
		return nil, err
	}

	if r.MatchExtension != nil {
		rule.MatchExtension, err = c.ParseMatchExtension(r.MatchExtension)
		if err != nil {
			return nil, err
		}
	}
	return rule, nil
}

type RulePayload struct {
	Op    RuleOperation `json:"op"`
	Index int           `json:"index"`
	Rule  *Rule         `json:"rule"`
}

type RuleRespPayload struct {
	Op      RuleOperation `json:"op"`
	Success bool          `json:"success"`
	Data    any           `json:"data"`
	Error   string        `json:"error"`
}

func NewRuleRespPayload(op RuleOperation, success bool, data any, err string) RuleRespPayload {
	return RuleRespPayload{
		Op:      op,
		Success: success,
		Data:    data,
		Error:   err,
	}
}

type Firewall struct {
	xdp       *xdpwall.Wall
	converter *ruleConverter
	ls        net.Listener

	ipSets map[string]*IPSet
	rules  []*Rule
}

func NewFirewall() *Firewall {
	var err error
	w := &Firewall{}
	w.ipSets = make(map[string]*IPSet)
	w.xdp, err = xdpwall.NewWall()
	if err != nil {
		log.Fatal(err)
	}
	w.converter = newRuleConverter()
	go w.listenSock()
	return w
}

func (f *Firewall) handleSock(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Println("error reading data:", err)
		return
	}
	log.Println("rule payload:", string(buffer[:n]))

	var payload RulePayload
	err = json.Unmarshal(buffer[:n], &payload)
	if err != nil {
		log.Println("error parse payload:", err)
		return
	}

	switch payload.Op {
	case OpAppend:
		err := f.AppendRule(payload.Rule)
		var resp RuleRespPayload
		if err != nil {
			resp = NewRuleRespPayload(payload.Op, false, nil, err.Error())
		} else {
			resp = NewRuleRespPayload(payload.Op, true, nil, "")
		}
		res, _ := json.Marshal(resp)
		_, err = conn.Write(res)
		if err != nil {
			log.Println(err)
		}
	case OpInsert:
		err := f.InsertRule(payload.Index, payload.Rule)
		var resp RuleRespPayload
		if err != nil {
			resp = NewRuleRespPayload(payload.Op, false, nil, err.Error())
		} else {
			resp = NewRuleRespPayload(payload.Op, true, nil, "")
		}
		res, _ := json.Marshal(resp)
		_, err = conn.Write(res)
		if err != nil {
			log.Println(err)
		}
	case OpDelete:
		err := f.DeleteRule(payload.Index)
		var resp RuleRespPayload
		if err != nil {
			resp = NewRuleRespPayload(payload.Op, false, nil, err.Error())
		} else {
			resp = NewRuleRespPayload(payload.Op, true, nil, "")
		}
		res, _ := json.Marshal(resp)
		_, err = conn.Write(res)
		if err != nil {
			log.Println(err)
		}
	case OpList:
		rules := f.ListRules()
		b, _ := json.Marshal(rules)
		resp := NewRuleRespPayload(payload.Op, true, string(b), "")
		res, _ := json.Marshal(resp)
		_, err := conn.Write(res)
		if err != nil {
			log.Println(err)
		}
	case OpClear:
	}
}

func (f *Firewall) listenSock() {
	var err error
	_ = os.Remove(SockFile)

	f.ls, err = net.Listen("unix", SockFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("server listening on unix domain socket:", SockFile)

	for {
		conn, err := f.ls.Accept()
		if err == io.EOF {
			return
		}
		if err != nil {
			continue
		}

		go f.handleSock(conn)
	}
}

func (f *Firewall) LookupIPSet(setName string) (*IPSet, error) {
	return f.ipSets[setName], nil
}

func (f *Firewall) CreateIPSet(setName string) error {
	err := f.xdp.CreateSet(str2hash(setName))
	if err != nil {
		return err
	}
	f.ipSets[setName] = &IPSet{Name: setName}
	return nil
}

func (f *Firewall) AppendIP(setName string, ips ...string) error {
	_, ok := f.ipSets[setName]
	if !ok {
		return errors.New("set does not exist")
	}

	var ipItems []xdpwall.FilterIpItem
	for _, ip := range ips {
		item, err := f.converter.ParseIPItem(ip)
		if err != nil {
			return err
		}
		ipItems = append(ipItems, item)
	}
	err := f.xdp.AppendIP(str2hash(setName), ipItems...)
	if err != nil {
		return err
	}

	f.ipSets[setName].Addrs = append(f.ipSets[setName].Addrs, ips...)
	return nil
}

func (f *Firewall) RemoveIP(setName string, ip string) error {
	ipSet, ok := f.ipSets[setName]
	if !ok {
		return errors.New("set does not exist")
	}

	ipItem, err := f.converter.ParseIPItem(ip)
	if err != nil {
		return err
	}
	err = f.xdp.RemoveIP(str2hash(setName), ipItem)
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

func (f *Firewall) ListRules() []*Rule {
	return f.rules
}

func (f *Firewall) InsertRule(pos int, r *Rule) error {
	size := len(f.rules)
	if pos > size {
		return fmt.Errorf("pos %d out of range", pos)
	}

	rule, err := f.converter.ParseRule(r)
	if err != nil {
		return err
	}
	if err = f.xdp.InsertRule(pos, rule); err != nil {
		return err
	}

	if pos == size {
		f.rules = append(f.rules, r)
	} else {
		f.rules = append(f.rules, nil)
		copy(f.rules[pos+1:], f.rules[pos:])
		f.rules[pos] = r
	}
	return nil
}

func (f *Firewall) AppendRule(rules ...*Rule) error {
	if len(rules) == 0 {
		return nil
	}

	var parsedRules []*xdpwall.Rule
	for _, r := range rules {
		rule, err := f.converter.ParseRule(r)
		if err != nil {
			return err
		}
		parsedRules = append(parsedRules, rule)
	}

	err := f.xdp.AppendRule(parsedRules...)
	if err != nil {
		return err
	}
	f.rules = append(f.rules, rules...)
	return nil
}

func (f *Firewall) DeleteRule(pos int) error {
	size := len(f.rules)
	if pos >= size {
		return fmt.Errorf("pos %d out of range", pos)
	}

	err := f.xdp.DeleteRule(pos)
	if err != nil {
		return err
	}
	f.rules = append(f.rules[:pos], f.rules[pos+1:]...)
	return nil
}

func (f *Firewall) loadFormat(format *RuleFormat) error {
	for _, ipset := range format.IPSets {
		err := f.CreateIPSet(ipset.Name)
		if err != nil {
			return err
		}
		err = f.AppendIP(ipset.Name, ipset.Addrs...)
		if err != nil {
			return err
		}
	}

	err := f.AppendRule(format.Rules...)
	if err != nil {
		return err
	}

	return nil
}

func (f *Firewall) LoadFromJson(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	var ruleFormat *RuleFormat
	err = json.Unmarshal(data, &ruleFormat)
	if err != nil {
		return err
	}

	return f.loadFormat(ruleFormat)
}

func (f *Firewall) LoadFromYaml(file string) error {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigFile(file)
	err := v.ReadInConfig()
	if err != nil {
		return err
	}

	var ruleFormat *RuleFormat
	err = v.Unmarshal(&ruleFormat)
	if err != nil {
		return err
	}

	return f.loadFormat(ruleFormat)
}

func (f *Firewall) receiveEvents() {
	for {
		select {
		case me, ok := <-f.xdp.ReadMatchEvent():
			if !ok {
				return
			}
			rule := f.rules[me.RuleIndex]
			if rule == nil {
				continue
			}
			rule.Packets++
			rule.Bytes += me.Bytes
			// log.Printf("rule.index: %d, rule.pkts: %d, rule.bytes: %d", me.RuleIndex, rule.Packets, rule.Bytes)
		}
	}
}

func (f *Firewall) Run() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if err := f.xdp.Attach(iface.Index); err != nil {
			return err
		}
		log.Printf("attached firewall to iface %s", iface.Name)
	}

	f.receiveEvents()

	return nil
}

func (f *Firewall) Stop() error {
	f.ls.Close()
	return f.xdp.Stop()
}
