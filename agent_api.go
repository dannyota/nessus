package nessus

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

type apiAgentList struct {
	Agents []apiAgent `json:"agents"`
}

type apiAgent struct {
	ID               int      `json:"id"`
	TotalAgents      int      `json:"total_agents"`
	UUID             string   `json:"uuid"`
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	ClusterGroupName string   `json:"cluster_group_name"`
	LinkStatus       string   `json:"link_status"`
	LinkGroups       string   `json:"link_groups"`
	NodeID           int      `json:"node_id"`
	AutoUnlinked     int      `json:"auto_unlinked"`
	UnlinkedOn       int64    `json:"unlinked_on"`
	Profile          string   `json:"profile"`
	ProfileUUID      string   `json:"profile_uuid"`
	Platform         string   `json:"platform"`
	Distro           string   `json:"distro"`
	UpgradeDistro    string   `json:"upgrade_distro"`
	IP               string   `json:"ip"`
	MACAddrs         string   `json:"mac_addrs"` // JSON-encoded array string
	CoreVersion      string   `json:"core_version"`
	CoreBuild        string   `json:"core_build"`
	LinkedOn         int64    `json:"linked_on"`
	LastConnect      int64    `json:"last_connect"`
	LastScanned      int64    `json:"last_scanned"`
	Groups           []string `json:"groups"`
	PluginFeedID     string   `json:"plugin_feed_id"`
}

// ListAgentsOptions configures agent listing.
type ListAgentsOptions struct {
	// Limit is the maximum number of agents to return.
	Limit int
	// Offset is the zero-based offset for paginated agent listing.
	Offset int
	// SortBy is the API field to sort by, e.g. "name".
	SortBy string
	// SortOrder is "asc" or "desc".
	SortOrder string
}

// ListAgents iterates all agents, calling fn for each one.
func (c *Client) ListAgents(ctx context.Context, fn func(Agent) error) error {
	return c.ListAgentsWithOptions(ctx, nil, fn)
}

// ListAgentsWithOptions iterates agents using optional pagination and sorting.
// When opts is nil, it calls the default /agents endpoint.
func (c *Client) ListAgentsWithOptions(ctx context.Context, opts *ListAgentsOptions, fn func(Agent) error) error {
	var resp apiAgentList
	if err := c.getJSON(ctx, agentListPath(opts), &resp); err != nil {
		return err
	}

	for _, a := range resp.Agents {
		agent := Agent{
			ID:               a.ID,
			TotalAgents:      a.TotalAgents,
			UUID:             a.UUID,
			Name:             a.Name,
			Status:           a.Status,
			ClusterGroupName: a.ClusterGroupName,
			LinkStatus:       a.LinkStatus,
			LinkGroups:       a.LinkGroups,
			NodeID:           a.NodeID,
			AutoUnlinked:     a.AutoUnlinked,
			UnlinkedOn:       a.UnlinkedOn,
			Profile:          a.Profile,
			ProfileUUID:      a.ProfileUUID,
			Platform:         a.Platform,
			Distro:           a.Distro,
			UpgradeDistro:    a.UpgradeDistro,
			IP:               a.IP,
			MACAddresses:     parseMACAddrs(a.MACAddrs),
			CoreVersion:      a.CoreVersion,
			CoreBuild:        a.CoreBuild,
			LinkedOn:         a.LinkedOn,
			LastConnect:      a.LastConnect,
			LastScanned:      a.LastScanned,
			Groups:           a.Groups,
			PluginFeedID:     a.PluginFeedID,
		}
		if err := fn(agent); err != nil {
			return err
		}
	}
	return nil
}

func agentListPath(opts *ListAgentsOptions) string {
	if opts == nil {
		return "/agents"
	}

	q := url.Values{}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
		q.Set("offset", strconv.Itoa(opts.Offset))
	} else if opts.Offset > 0 {
		q.Set("offset", strconv.Itoa(opts.Offset))
	}
	if opts.SortBy != "" {
		q.Set("sort_by", opts.SortBy)
	}
	if opts.SortOrder != "" {
		q.Set("sort_order", opts.SortOrder)
	}
	if len(q) == 0 {
		return "/agents"
	}
	return "/agents?" + q.Encode()
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
