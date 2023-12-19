package trafficbus

import (
	"testing"
)

func TestIPSet(t *testing.T) {
	store := NewWall()
	setName := "myset"

	store.SetIPSet(setName, &IPSetEntry{
		Name: setName,
	})

	store.AppendIP(setName, "1.1.1.1/0", "2.2.2.2")
	if len(store.GetIPSet(setName).Addrs) != 2 {
		t.Fatal("the ipset length should be 2")
	}

	addrs := store.GetIPSet(setName).Addrs
	if addrs[0] != "1.1.1.1/0" || addrs[1] != "2.2.2.2" {
		t.Fatal("wrong ipset content")
	}

	store.DelIP(setName, "2.2.2.2")
	if len(store.GetIPSet(setName).Addrs) != 1 {
		t.Fatal("the ipset length should be 1")
	}

	store.DelIPSet(setName)
	if store.GetIPSet(setName) != nil {
		t.Fatal("the ipset length should be nil")
	}
}

func TestRuleSet(t *testing.T) {
	store := NewWall()
	iface := "lo"

	store.InsertRule(iface, 0, &Rule{Num: 1, Target: "A"})
	store.InsertRule(iface, 1, &Rule{Num: 2, Target: "B"})
	store.InsertRule(iface, 2, &Rule{Num: 3, Target: "C"})
	store.InsertRule(iface, 1, &Rule{Num: 2, Target: "B1"})
	if len(store.GetRules(iface)) != 4 {
		t.Fatal("the rule length should be 4")
	}

	rules := store.GetRules(iface)
	if rules[0].Target != "A" ||
		rules[1].Target != "B1" ||
		rules[2].Target != "B" ||
		rules[3].Target != "C" {
		t.Fatal("wrong rule content")
	}

	store.DelRule(iface, 1)
	if len(store.GetRules(iface)) != 3 {
		t.Fatal("the rule length should be 3")
	}

	store.AppendRule(iface, &Rule{Target: "D"}, &Rule{Target: "E"})
	if len(store.GetRules(iface)) != 5 {
		t.Fatal("the rule length should be 5")
	}
	rules = store.GetRules(iface)
	if rules[3].Target != "D" || rules[4].Target != "E" {
		t.Fatal("wrong rule content")
	}

	store.DelRules(iface)

	if len(store.GetRules(iface)) != 0 {
		t.Fatal("the rule length should be 0")
	}
}

func TestLoadFromJSON(t *testing.T) {
	s := NewWall()

	err := s.LoadFromJSON("./testdata/rule.json")
	if err != nil {
		t.Error(err)
	}

	if s.GetIPSet("myset") == nil {
		t.Fatal("nil ipset")
	}

	if s.GetRules("lo") == nil {
		t.Error("nil rules")
	}
}