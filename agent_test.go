package nessus

import "testing"

func TestExtractAgentID(t *testing.T) {
	t.Run("found in plugin 110230", func(t *testing.T) {
		host := ExportHost{
			Findings: []Finding{
				{PluginID: 22869, Output: "some info"},
				{PluginID: PluginIDNessusAgent, Output: "Nessus Agent Installed\n  Agent ID : a1b2c3d4-e5f6-7890-abcd-ef1234567890\n  Version  : 10.6.1"},
			},
		}
		id := ExtractAgentID(host)
		if id != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
			t.Errorf("got %q", id)
		}
	})

	t.Run("found in legacy plugin 100574", func(t *testing.T) {
		host := ExportHost{
			Findings: []Finding{
				{PluginID: PluginIDNessusAgentLegacy, Output: "Agent ID: deadbeef-1234-5678-9abc-def012345678"},
			},
		}
		id := ExtractAgentID(host)
		if id != "deadbeef-1234-5678-9abc-def012345678" {
			t.Errorf("got %q", id)
		}
	})

	t.Run("not found", func(t *testing.T) {
		host := ExportHost{
			Findings: []Finding{
				{PluginID: 22869, Output: "SSH server info"},
				{PluginID: 10001, Output: "some vuln"},
			},
		}
		id := ExtractAgentID(host)
		if id != "" {
			t.Errorf("got %q, want empty", id)
		}
	})

	t.Run("empty findings", func(t *testing.T) {
		host := ExportHost{}
		id := ExtractAgentID(host)
		if id != "" {
			t.Errorf("got %q, want empty", id)
		}
	})

	t.Run("ParseAgentID directly", func(t *testing.T) {
		id := ParseAgentID("Nessus Agent Installed\n  Agent ID : abcdef01-2345-6789-abcd-ef0123456789\n  Version  : 10.6.1")
		if id != "abcdef01-2345-6789-abcd-ef0123456789" {
			t.Errorf("got %q", id)
		}
	})

	t.Run("ParseAgentID empty", func(t *testing.T) {
		id := ParseAgentID("no agent here")
		if id != "" {
			t.Errorf("got %q, want empty", id)
		}
	})

	t.Run("agent plugin without id in output", func(t *testing.T) {
		host := ExportHost{
			Findings: []Finding{
				{PluginID: PluginIDNessusAgent, Output: "Nessus Agent Installed\n  Version : 10.6.1"},
			},
		}
		id := ExtractAgentID(host)
		if id != "" {
			t.Errorf("got %q, want empty", id)
		}
	})
}
