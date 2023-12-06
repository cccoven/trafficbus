package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cccoven/trafficbus"
	"github.com/cccoven/trafficbus/internal/ebpf/xdp"
)

var (
	ruleFile string
)

func init() {
	flag.StringVar(&ruleFile, "f", "", "the rule set file")
	flag.Parse()
}

func main() {
	ruleSet, err := trafficbus.LoadRuleSetFromJSON(ruleFile)
	if err != nil {
		log.Fatal("failed to load rule file: ", err.Error())
	}

	for _, rs := range ruleSet {
		go func(rs trafficbus.RuleSet) {
			rules, err := xdp.ConvertToXdpRule(rs.Rules)
			if err != nil {
				log.Printf("iface %s failed to convert rule: %s", rs.IFace, err.Error())
			}
			progXDP := xdp.NewXdp(rs.IFace, rules)
			progXDP.Run()
		}(rs)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	os.Exit(0)
}
