package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/cccoven/trafficbus"
	"github.com/spf13/cobra"
)

type WallRunOptions struct {
	RuleFile string
}

type WallRuleOptions struct {
	Op             string
	Index          int
	Rule           *trafficbus.Rule
	MatchExtension bool
	Set            bool
	UDP            bool
	TCP            bool
}

var wallRunOptions WallRunOptions
var wallRuleOptions = WallRuleOptions{Rule: &trafficbus.Rule{}}

var wallCmd = &cobra.Command{
	Use:   "wall",
	Short: "Module firewall.",
}

var wallRunCmd = &cobra.Command{
	Use:           "run",
	Short:         "Run firewall.",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          wallRun,
}

var wallRuleCmd = &cobra.Command{
	Use:           "rule",
	Short:         "Define a rule for firewall.",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          wallRuleRun,
}

func init() {
	wallCmd.AddCommand(wallRunCmd, wallRuleCmd)
	wallRunCmd.Flags().StringVarP(&wallRunOptions.RuleFile, "rule-file", "f", "", "Firewall rule file")

	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Op, "opration", "o", "", "Operation on this rule")
	wallRuleCmd.Flags().IntVarP(&wallRuleOptions.Index, "num", "n", -1, "Number of this rule")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Interface, "interface", "i", "", "Network interface")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Target, "target", "t", "", "Target")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Protocol, "protocol", "p", "", "IP protocol")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Source, "source", "s", "0.0.0.0/0", "Source address")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Destination, "destination", "d", "0.0.0.0/0", "Destination address")

	wallRuleCmd.Flags().BoolVarP(&wallRuleOptions.MatchExtension, "match-extension", "m", false, "Enable match extension")
	wallRuleCmd.Flags().BoolVar(&wallRuleOptions.TCP, "tcp", false, "Protocol TCP")
}

func wallRun(cmd *cobra.Command, args []string) error {
	wall := trafficbus.NewFirewall()

	if wallRunOptions.RuleFile != "" {
		err := wall.LoadFromYaml(wallRunOptions.RuleFile)
		if err != nil {
			return fmt.Errorf("failed to start command wall: %s", err.Error())
		}
	}

	if err := wall.Run(); err != nil {
		return err
	}
	return nil
}

func wallRuleRun(cmd *cobra.Command, args []string) error {
	conn, err := net.Dial("unix", trafficbus.SockFile)
	if err != nil {
		return fmt.Errorf("connect failed: %s. please make sure the firewall is running", err.Error())
	}
	defer conn.Close()

	var op trafficbus.RuleOperation
	switch wallRuleOptions.Op {
	case "append":
		op = trafficbus.OpAppend
	case "insert":
		op = trafficbus.OpInsert
	case "delete":
		op = trafficbus.OpDelete
	case "clear":
		op = trafficbus.OpClear
	case "list":
		op = trafficbus.OpList
	default:
		return errors.New("invalid operation")
	}

	if wallRuleOptions.MatchExtension {
		wallRuleOptions.Rule.MatchExtension = &trafficbus.MatchExtension{}
	}

	payload := trafficbus.RulePayload{
		Op:    op,
		Index: wallRuleOptions.Index,
		Rule:  wallRuleOptions.Rule,
	}
	rule, _ := json.Marshal(payload)
	_, err = conn.Write(rule)
	if err != nil {
		return err
	}

	return nil
}
