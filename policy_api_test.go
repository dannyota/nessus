package nessus

import (
	"context"
	"testing"
)

func TestListPolicies(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/policies": `{
			"policies": [
				{
					"id": 10,
					"name": "baseline",
					"description": "standard checks",
					"owner": "owner-a",
					"owner_id": 7,
					"visibility": "private",
					"shared": 0,
					"user_permissions": 128,
					"template_uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
					"is_agent": true,
					"is_scap": 0,
					"has_credentials": 1,
					"no_target": "false",
					"plugin_filters": [{"filter": "severity"}],
					"creation_date": 1700000000,
					"last_modification_date": 1700001000
				}
			]
		}`,
	})

	policies, err := client.ListPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("len = %d, want 1", len(policies))
	}

	p := policies[0]
	if p.ID != 10 {
		t.Errorf("ID = %d", p.ID)
	}
	if p.Name != "baseline" {
		t.Errorf("Name = %q", p.Name)
	}
	if p.Description != "standard checks" {
		t.Errorf("Description = %q", p.Description)
	}
	if p.Owner != "owner-a" {
		t.Errorf("Owner = %q", p.Owner)
	}
	if p.OwnerID != 7 {
		t.Errorf("OwnerID = %d", p.OwnerID)
	}
	if p.Visibility != "private" {
		t.Errorf("Visibility = %q", p.Visibility)
	}
	if p.UserPermissions != 128 {
		t.Errorf("UserPermissions = %d", p.UserPermissions)
	}
	if p.TemplateUUID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("TemplateUUID = %q", p.TemplateUUID)
	}
	if !p.IsAgent {
		t.Errorf("IsAgent = false, want true")
	}
	if p.HasCredentials != 1 {
		t.Errorf("HasCredentials = %d", p.HasCredentials)
	}
	if p.CreationDate != 1700000000 {
		t.Errorf("CreationDate = %d", p.CreationDate)
	}
	if p.LastModificationDate != 1700001000 {
		t.Errorf("LastModificationDate = %d", p.LastModificationDate)
	}
}

func TestListPolicies_Empty(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/policies": `{"policies": []}`,
	})

	policies, err := client.ListPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Errorf("len = %d, want 0", len(policies))
	}
}
