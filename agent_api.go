package nessus

import (
	"context"
	"encoding/json"
)

type apiAgentList struct {
	Agents []apiAgent `json:"agents"`
}

type apiAgent struct {
	ID           int      `json:"id"`
	UUID         string   `json:"uuid"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Platform     string   `json:"platform"`
	Distro       string   `json:"distro"`
	IP           string   `json:"ip"`
	MACAddrs     string   `json:"mac_addrs"` // JSON-encoded array string
	CoreVersion  string   `json:"core_version"`
	CoreBuild    string   `json:"core_build"`
	LinkedOn     int64    `json:"linked_on"`
	LastConnect  int64    `json:"last_connect"`
	LastScanned  int64    `json:"last_scanned"`
	Groups       []string `json:"groups"`
	PluginFeedID string   `json:"plugin_feed_id"`
}

// ListAgents iterates all agents, calling fn for each one.
func (c *Client) ListAgents(ctx context.Context, fn func(Agent) error) error {
	var resp apiAgentList
	if err := c.getJSON(ctx, "/agents", &resp); err != nil {
		return err
	}

	for _, a := range resp.Agents {
		agent := Agent{
			ID:           a.ID,
			UUID:         a.UUID,
			Name:         a.Name,
			Status:       a.Status,
			Platform:     a.Platform,
			Distro:       a.Distro,
			IP:           a.IP,
			MACAddresses: parseMACAddrs(a.MACAddrs),
			CoreVersion:  a.CoreVersion,
			CoreBuild:    a.CoreBuild,
			LinkedOn:     a.LinkedOn,
			LastConnect:   a.LastConnect,
			LastScanned:   a.LastScanned,
			Groups:       a.Groups,
			PluginFeedID: a.PluginFeedID,
		}
		if err := fn(agent); err != nil {
			return err
		}
	}
	return nil
}

// parseMACAddrs parses the JSON-encoded MAC address string from the API.
// The API returns mac_addrs as a JSON string like: "[\"aa:bb:cc:dd:ee:ff\"]"
func parseMACAddrs(raw string) []string {
	if raw == "" {
		return nil
	}
	var addrs []string
	if json.Unmarshal([]byte(raw), &addrs) != nil {
		return nil
	}
	return addrs
}
