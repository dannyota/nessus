package nessus

import "regexp"

// Nessus Agent plugin IDs.
const (
	PluginIDNessusAgent       = 110230
	PluginIDNessusAgentLegacy = 100574
)

var agentIDPattern = regexp.MustCompile(`Agent\s+ID\s*:\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)

// ExtractAgentID extracts the Nessus Agent UUID from an ExportHost's findings.
// It looks for plugin 110230 or 100574 (Tenable Nessus Agent Installed) and
// parses the Agent ID from the plugin output text.
// Returns empty string if no agent ID is found.
func ExtractAgentID(host ExportHost) string {
	for _, f := range host.Findings {
		if f.PluginID == PluginIDNessusAgent || f.PluginID == PluginIDNessusAgentLegacy {
			if id := ParseAgentID(f.Output); id != "" {
				return id
			}
		}
	}
	return ""
}

// ParseAgentID extracts a Nessus Agent UUID from plugin output text.
// Use this with GetPluginOutput results for plugin 110230 or 100574.
func ParseAgentID(output string) string {
	matches := agentIDPattern.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
