package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/cccoven/trafficbus"
	"github.com/spf13/cobra"
)

type WallRunOptions struct {
	RuleFile string
}

type WallRuleOptions struct {
	Append         bool
	Insert         int
	Delete         int
	List           bool
	Rule           *trafficbus.Rule
	MatchExtension bool
	Set            bool
	UDP            bool
	TCP            bool
}

var wallRunOptions WallRunOptions
var wallRuleOptions = WallRuleOptions{
	Rule: &trafficbus.Rule{
		MatchExtension: &trafficbus.MatchExtension{},
	},
}

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
	wallRunCmd.Flags().StringVarP(&wallRunOptions.RuleFile, "rule-file", "f", "", "firewall rule file")

	wallRuleCmd.Flags().BoolVarP(&wallRuleOptions.Append, "append", "A", false, "append a rule")
	wallRuleCmd.Flags().IntVarP(&wallRuleOptions.Insert, "insert", "I", 0, "insert a rule")
	wallRuleCmd.Flags().IntVarP(&wallRuleOptions.Delete, "delete", "D", 0, "delete a rule")
	wallRuleCmd.Flags().BoolVarP(&wallRuleOptions.List, "list", "L", false, "list rules")

	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Interface, "interface", "i", "ALL", "network interface")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Target, "target", "t", "", "target")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Protocol, "protocol", "p", "", "protocol")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Source, "source", "s", "0.0.0.0/0", "source address")
	wallRuleCmd.Flags().StringVarP(&wallRuleOptions.Rule.Destination, "destination", "d", "0.0.0.0/0", "destination address")

	wallRuleCmd.Flags().BoolVarP(&wallRuleOptions.MatchExtension, "match-extension", "m", false, "enable match extension")
	wallRuleCmd.Flags().BoolVar(&wallRuleOptions.TCP, "tcp", false, "protocol TCP")
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

	var payload trafficbus.RulePayload

	if wallRuleOptions.Append {
		payload.Op = trafficbus.OpAppend
		payload.Rule = wallRuleOptions.Rule
	}
	if wallRuleOptions.Insert > 0 {
		payload.Op = trafficbus.OpInsert
		payload.Rule = wallRuleOptions.Rule
		payload.Index = wallRuleOptions.Insert - 1
	}
	if wallRuleOptions.Delete > 0 {
		payload.Op = trafficbus.OpDelete
		payload.Rule = wallRuleOptions.Rule
		payload.Index = wallRuleOptions.Delete - 1
	}
	if wallRuleOptions.List {
		payload.Op = trafficbus.OpList
	}

	rule, _ := json.Marshal(payload)
	_, err = conn.Write(rule)
	if err != nil {
		return err
	}

	var respPayload trafficbus.RuleRespPayload
	resp, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	err = json.Unmarshal(resp, &respPayload)
	if err != nil {
		return err
	}

	switch respPayload.Op {
	case trafficbus.OpAppend:
	case trafficbus.OpInsert:
	case trafficbus.OpDelete:
	case trafficbus.OpList:
		if respPayload.Data != nil {
			var rules []*trafficbus.Rule
			err = json.Unmarshal([]byte(respPayload.Data.(string)), &rules)
			if err != nil {
				return err
			}
			printRuleList(rules)
		}
	case trafficbus.OpClear:
	}

	return nil
}

func printRuleList(rules []*trafficbus.Rule) {
	const format = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n"
	tw := tabwriter.NewWriter(os.Stdout, 10, 10, 10, ' ', 0)
	fmt.Fprintf(tw, format, "Num", "Packets", "Bytes", "Interface", "Target", "Protocol", "Source", "Destination")

	for i, r := range rules {
		if r.Interface == "" {
			r.Interface = "ALL"
		}
		if r.Protocol == "" {
			r.Protocol = "ALL"
		}
		fmt.Fprintf(tw, format, strconv.Itoa(i+1), strconv.Itoa(r.Packets), strconv.FormatUint(r.Bytes, 10), r.Interface, r.Target, r.Protocol, r.Source, r.Destination)
	}

	tw.Flush()
}
