package nessus

import (
	"context"
	"testing"
)

func TestListAgentGroups(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/agent-groups": `{
			"groups": [
				{
					"id": 1,
					"name": "group-a",
					"agents_count": 6,
					"owner": "owner-a",
					"owner_id": 1,
					"owner_name": "owner-a",
					"shared": 1,
					"user_permissions": 128,
					"timestamp": 1700000500,
					"creation_date": 1700000000,
					"last_modification_date": 1700001000
				},
				{
					"id": 2,
					"name": "group-b",
					"agents_count": 2,
					"owner_id": 1,
					"owner_name": "owner-a",
					"creation_date": 1700000100,
					"last_modification_date": 1700001100
				}
			]
		}`,
	})

	groups, err := client.ListAgentGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(groups) != 2 {
		t.Fatalf("len = %d, want 2", len(groups))
	}

	g := groups[0]
	if g.ID != 1 {
		t.Errorf("ID = %d", g.ID)
	}
	if g.Name != "group-a" {
		t.Errorf("Name = %q", g.Name)
	}
	if g.AgentsCount != 6 {
		t.Errorf("AgentsCount = %d", g.AgentsCount)
	}
	if g.OwnerName != "owner-a" {
		t.Errorf("OwnerName = %q", g.OwnerName)
	}
	if g.Owner != "owner-a" {
		t.Errorf("Owner = %q", g.Owner)
	}
	if g.Shared != 1 {
		t.Errorf("Shared = %d", g.Shared)
	}
	if g.UserPermissions != 128 {
		t.Errorf("UserPermissions = %d", g.UserPermissions)
	}
	if g.Timestamp != 1700000500 {
		t.Errorf("Timestamp = %d", g.Timestamp)
	}
	if g.CreationDate != 1700000000 {
		t.Errorf("CreationDate = %d", g.CreationDate)
	}
}

func TestListAgentGroups_Empty(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/agent-groups": `{"groups": []}`,
	})

	groups, err := client.ListAgentGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Errorf("len = %d, want 0", len(groups))
	}
}
