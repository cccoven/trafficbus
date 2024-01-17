package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/cccoven/trafficbus"
	"github.com/spf13/cobra"
)

type WallRunOptions struct {
	RuleFile string
}

type WallRuleOptions struct {
	Rule           *trafficbus.Rule
	MatchExtension bool
	Set            bool
	UDP            bool
	TCP            bool
}

var wallRunOptions WallRunOptions

// var wallRuleOptions WallRuleOptions
var wallRuleOptions = WallRuleOptions{
	Rule: &trafficbus.Rule{
		// MatchExtension: &trafficbus.MatchExtension{
		// 	Set: &trafficbus.SetExtension{},
		// 	UDP: &trafficbus.UDPExtension{},
		// 	TCP: &trafficbus.TCPExtension{
		// 		Flags: &trafficbus.TCPFlags{},
		// 	},
		// 	MultiPort: &trafficbus.MultiPortExtension{},
		// },
	},
}

var wallCmd = &cobra.Command{
	Use:   "wall",
	Short: "Module firewall.",
}

var wallRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run firewall.",
	RunE:  wallRun,
}

var wallRuleCmd = &cobra.Command{
	Use:     "rule",
	Short:   "Define a rule for firewall.",
	PreRunE: wallRulePreRun,
	RunE:    wallRuleRun,
}

func init() {
	wallCmd.AddCommand(wallRunCmd, wallRuleCmd)
	wallRunCmd.Flags().StringVarP(&wallRunOptions.RuleFile, "rule-file", "f", "rule.yaml", "Firewall rule file")

	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Interface, "interface", "i", "", "Network interface")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Target, "target", "t", "", "Target")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Protocol, "protocol", "p", "", "IP protocol")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Source, "source", "s", "0.0.0.0/0", "Source address")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Destination, "destination", "d", "0.0.0.0/0", "destination address")
	wallRuleCmd.Flags().BoolVar(&wallRuleOptions.TCP, "tcp", false, "Protocol TCP")
}

func wallRun(cmd *cobra.Command, args []string) error {
	// wall = trafficbus.NewWall(&trafficbus.WallOptions{})
	// if err := wall.Run(); err != nil {
	// 	return fmt.Errorf("failed to start command wall: %s", err.Error())
	// }

	// wait()
	// wall.Stop()

	wall := trafficbus.NewFirewall()

	err := wall.LoadFromYaml(wallRunOptions.RuleFile)
	if err != nil {
		return fmt.Errorf("failed to start command wall: %s", err.Error())
	}

	wall.Run()

	return nil
}

func wallRulePreRun(cmd *cobra.Command, args []string) error {
	fmt.Println("prerun")
	return nil
}

func wallRuleRun(cmd *cobra.Command, args []string) error {
	fmt.Println(wallRuleOptions.Rule)

	conn, err := net.Dial("unix", trafficbus.SockFile)
	if err != nil {
		return err
	}
	defer conn.Close()

	payload := trafficbus.RulePayload{
		Op:    trafficbus.OpAppend,
		Index: 0,
		Rule:  wallRuleOptions.Rule,
	}
	rule, _ := json.Marshal(payload)
	_, err = conn.Write(rule)
	if err != nil {
		return err
	}

	return nil
}
