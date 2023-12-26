package trafficbus

import (
	"fmt"
	"log"
	"testing"
	"time"
)

func handleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printIpSet(wall *Wall, setName string) {
	ipSet, err := wall.LookupIpSet("myset")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Name:\t%s\n", ipSet.Name)
	fmt.Println("Addresses: ")
	for _, addr := range ipSet.Addrs {
		fmt.Printf("\t%s\n", addr)
	}
}

func TestIPSet(t *testing.T) {
	wall := NewWall()

	err := wall.CreateIpSet("myset")
	handleError(err)

	err = wall.AppendIp("myset", "127.0.0.1", "0.0.0.0", "192.168.0.0/16", "1.1.1.1")
	handleError(err)

	printIpSet(wall, "myset")

	fmt.Printf("\nRemove...\n\n")

	err = wall.RemoveIp("myset", "0.0.0.0")
	handleError(err)
	err = wall.RemoveIp("myset", "1.1.1.1")
	handleError(err)

	printIpSet(wall, "myset")
}

func printRuleSet(wall *Wall, iface string) {
	rules, err := wall.LookupRuleSet(iface)
	if err != nil {
		log.Fatal(err)
	}

	for i, rule := range rules {
		fmt.Printf("index: %d, target: %s, protocol: %s, source: %s, destination: %s\n", i, rule.Target, rule.Protocol, rule.Source, rule.Destination)
	}
}

func TestRuleSet(t *testing.T) {
	wall := NewWall()
	data := map[string][]*Rule{
		"lo": {
			{
				Target:   "DROP",
				Protocol: "ICMP",
			},
			{
				Target:   "ACCEPT",
				Protocol: "TCP",
				MatchExtension: MatchExtension{
					TCP: TCPExtension{
						DstPort: 8080,
					},
				},
			},
			{
				Target:   "DROP",
				Protocol: "UDP",
				MatchExtension: MatchExtension{
					UDP: UDPExtension{
						DstPort: 8081,
					},
				},
			},
		},
	}

	for iface, rules := range data {
		err := wall.CreateRuleSet(iface)
		handleError(err)
		for i, rule := range rules {
			err = wall.InsertRule(iface, i, rule)
			handleError(err)
		}
	}

	printRuleSet(wall, "lo")

	fmt.Println("Insert...")

	err := wall.InsertRule("lo", 1, &Rule{
		Target:   "ACCEPT",
		Protocol: "UDP",
		Source:   "127.0.0.0/8",
	})
	handleError(err)

	err = wall.AppendRule("lo", &Rule{Target: "ACCEPT"})
	handleError(err)

	printRuleSet(wall, "lo")

	fmt.Println("Remove...")

	wall.RemoveRule("lo", 1)

	printRuleSet(wall, "lo")

	err = wall.Run()
	handleError(err)

	for {
		time.Sleep(5 * time.Second)
	}
}

func TestLoadFromJSON(t *testing.T) {}
