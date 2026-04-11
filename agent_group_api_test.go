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
					"name": "production-servers",
					"agents_count": 6,
					"owner_id": 1,
					"owner_name": "admin",
					"creation_date": 1700000000,
					"last_modification_date": 1700001000
				},
				{
					"id": 2,
					"name": "staging-servers",
					"agents_count": 2,
					"owner_id": 1,
					"owner_name": "admin",
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
	if g.Name != "production-servers" {
		t.Errorf("Name = %q", g.Name)
	}
	if g.AgentsCount != 6 {
		t.Errorf("AgentsCount = %d", g.AgentsCount)
	}
	if g.OwnerName != "admin" {
		t.Errorf("OwnerName = %q", g.OwnerName)
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
