package nessus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListAgents(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/agents": `{
			"agents": [
				{
					"id": 1,
					"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
					"name": "agent-01",
					"status": "online",
					"platform": "LINUX",
					"distro": "es9-x86-64",
					"ip": "192.0.2.1",
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
					"name": "agent-02",
					"status": "offline",
					"platform": "WINDOWS",
					"distro": "win-x86-64",
					"ip": "192.0.2.2",
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
	if a.Name != "agent-01" {
		t.Errorf("Name = %q", a.Name)
	}
	if a.Status != "online" {
		t.Errorf("Status = %q", a.Status)
	}
	if a.Platform != "LINUX" {
		t.Errorf("Platform = %q", a.Platform)
	}
	if a.IP != "192.0.2.1" {
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
					"ip": "192.0.2.1",
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

func TestListAgentsWithOptions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != "limit=50&offset=50&sort_by=name&sort_order=asc" {
			t.Errorf("query = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"agents": [
				{
					"id": 3,
					"total_agents": 163,
					"uuid": "33333333-3333-3333-3333-333333333333",
					"name": "agent-03",
					"status": "online",
					"cluster_group_name": "cluster-a",
					"link_status": "linked",
					"link_groups": "group-a",
					"node_id": 42,
					"auto_unlinked": 0,
					"unlinked_on": 0,
					"profile": "default",
					"profile_uuid": "profile-uuid",
					"platform": "LINUX",
					"distro": "es9-x86-64",
					"upgrade_distro": "el9-x86-64",
					"ip": "192.0.2.3",
					"mac_addrs": "[\"AA:BB:CC:DD:EE:04\"]",
					"core_version": "10.8.3",
					"core_build": "10",
					"linked_on": 1700000200,
					"last_connect": 1700001200,
					"last_scanned": 1700002200,
					"groups": ["group-a"],
					"plugin_feed_id": "202601020000"
				}
			]
		}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, WithAPIKeys("test-access", "test-secret"))
	if err != nil {
		t.Fatal(err)
	}

	var agents []Agent
	err = client.ListAgentsWithOptions(context.Background(), &ListAgentsOptions{
		Limit:     50,
		Offset:    50,
		SortBy:    "name",
		SortOrder: "asc",
	}, func(a Agent) error {
		agents = append(agents, a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Fatalf("len = %d, want 1", len(agents))
	}
	a := agents[0]
	if a.TotalAgents != 163 {
		t.Errorf("TotalAgents = %d", a.TotalAgents)
	}
	if a.LinkStatus != "linked" {
		t.Errorf("LinkStatus = %q", a.LinkStatus)
	}
	if a.ClusterGroupName != "cluster-a" {
		t.Errorf("ClusterGroupName = %q", a.ClusterGroupName)
	}
	if a.NodeID != 42 {
		t.Errorf("NodeID = %d", a.NodeID)
	}
	if a.ProfileUUID != "profile-uuid" {
		t.Errorf("ProfileUUID = %q", a.ProfileUUID)
	}
	if a.UpgradeDistro != "el9-x86-64" {
		t.Errorf("UpgradeDistro = %q", a.UpgradeDistro)
	}
}
