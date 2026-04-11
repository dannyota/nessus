package nessus

import (
	"context"
	"testing"
)

func TestListAgents(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/agents": `{
			"agents": [
				{
					"id": 1,
					"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
					"name": "web-01",
					"status": "online",
					"platform": "LINUX",
					"distro": "es9-x86-64",
					"ip": "10.0.0.1",
					"mac_addrs": "[\"AA:BB:CC:DD:EE:01\",\"AA:BB:CC:DD:EE:02\"]",
					"core_version": "10.8.2",
					"core_build": "9",
					"linked_on": 1700000000,
					"last_connect": 1700001000,
					"last_scanned": 1700002000,
					"groups": ["group-a", "group-b"],
					"plugin_feed_id": "202601010000"
				},
				{
					"id": 2,
					"uuid": "11111111-2222-3333-4444-555555555555",
					"name": "db-01",
					"status": "offline",
					"platform": "WINDOWS",
					"distro": "win-x86-64",
					"ip": "10.0.0.2",
					"mac_addrs": "[\"AA:BB:CC:DD:EE:03\"]",
					"core_version": "10.8.1",
					"core_build": "8",
					"linked_on": 1700000100,
					"last_connect": 1700001100,
					"last_scanned": 1700002100,
					"groups": ["group-b"],
					"plugin_feed_id": "202601010000"
				}
			]
		}`,
	})

	var agents []Agent
	err := client.ListAgents(context.Background(), func(a Agent) error {
		agents = append(agents, a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(agents) != 2 {
		t.Fatalf("len = %d, want 2", len(agents))
	}

	a := agents[0]
	if a.ID != 1 {
		t.Errorf("ID = %d", a.ID)
	}
	if a.UUID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("UUID = %q", a.UUID)
	}
	if a.Name != "web-01" {
		t.Errorf("Name = %q", a.Name)
	}
	if a.Status != "online" {
		t.Errorf("Status = %q", a.Status)
	}
	if a.Platform != "LINUX" {
		t.Errorf("Platform = %q", a.Platform)
	}
	if a.IP != "10.0.0.1" {
		t.Errorf("IP = %q", a.IP)
	}
	if len(a.MACAddresses) != 2 || a.MACAddresses[0] != "AA:BB:CC:DD:EE:01" {
		t.Errorf("MACAddresses = %v", a.MACAddresses)
	}
	if len(a.Groups) != 2 || a.Groups[0] != "group-a" {
		t.Errorf("Groups = %v", a.Groups)
	}
	if a.CoreVersion != "10.8.2" {
		t.Errorf("CoreVersion = %q", a.CoreVersion)
	}
	if a.LinkedOn != 1700000000 {
		t.Errorf("LinkedOn = %d", a.LinkedOn)
	}
}

func TestListAgents_Empty(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/agents": `{"agents": []}`,
	})

	var count int
	err := client.ListAgents(context.Background(), func(Agent) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestListAgents_NullMACAddrs(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/agents": `{
			"agents": [
				{
					"id": 1,
					"uuid": "abc",
					"name": "test",
					"status": "online",
					"platform": "LINUX",
					"ip": "10.0.0.1",
					"mac_addrs": "",
					"groups": []
				}
			]
		}`,
	})

	var agents []Agent
	err := client.ListAgents(context.Background(), func(a Agent) error {
		agents = append(agents, a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Fatalf("len = %d", len(agents))
	}
	if agents[0].MACAddresses != nil {
		t.Errorf("MACAddresses = %v, want nil", agents[0].MACAddresses)
	}
}
