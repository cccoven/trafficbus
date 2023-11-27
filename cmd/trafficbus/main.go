package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cccoven/trafficbus"
	"github.com/cccoven/trafficbus/internal/ebpf/xdp"
)

func main() {
	data, err := os.ReadFile("rule.json")
	if err != nil {
		log.Fatal("failed to load rules: ", err.Error())
	}
	var ruleSet []trafficbus.RuleSet
	err = json.Unmarshal(data, &ruleSet)
	if err != nil {
		log.Fatal("failed to unmarshal rule data: ", err.Error())
	}

	for _, rs := range ruleSet {
		go func(rs trafficbus.RuleSet) {
			progXDP := xdp.NewXDP(rs.IFace)
			progXDP.Run()
		}(rs)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	os.Exit(0)
}
