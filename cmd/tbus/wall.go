package main

import (
	"fmt"

	"github.com/cccoven/trafficbus"
	"github.com/spf13/cobra"
)

type WallRunOptions struct {
	RuleFile string
}

type WallRuleOptions struct {
	Interface      string
	Target         string
	Protocol       string
	Source         string
	Destination    string
	MatchExtension bool
	Set bool
	UDP bool
	TCP bool
}

var wallRunOptions WallRunOptions
var wallRuleOptions WallRuleOptions

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
	Use:   "rule",
	Short: "Define a rule for firewall.",
	RunE:  wallRuleRun,
}

func init() {
	wallCmd.AddCommand(wallRunCmd, wallRuleCmd)
	wallRunCmd.Flags().StringVarP(&wallRunOptions.RuleFile, "rule-file", "f", "rule.yaml", "The firewall rule file")

	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Interface, "interface", "i", "", "The network interface")
	wallRuleCmd.Flags().BoolVar(&wallRuleOptions.TCP, "tcp", false, "Protocol TCP")
}

func wallRun(cmd *cobra.Command, args []string) error {
	wall := trafficbus.NewWall(&trafficbus.WallOptions{})
	if err := wall.Run(); err != nil {
		return fmt.Errorf("failed to start command wall: %s", err.Error())
	}

	wait()
	wall.Stop()
	return nil
}

func wallRuleRun(cmd *cobra.Command, args []string) error {
	fmt.Println(wallRuleOptions.Interface)
	fmt.Println(wallRuleOptions.TCP)
	return nil
}
