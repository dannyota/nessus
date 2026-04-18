package nessus

import "context"

type apiAgentGroupList struct {
	Groups []apiAgentGroup `json:"groups"`
}

type apiAgentGroup struct {
	ID                   int    `json:"id"`
	Name                 string `json:"name"`
	AgentsCount          int    `json:"agents_count"`
	Owner                string `json:"owner"`
	OwnerID              int    `json:"owner_id"`
	OwnerName            string `json:"owner_name"`
	Shared               int    `json:"shared"`
	UserPermissions      int    `json:"user_permissions"`
	Timestamp            int64  `json:"timestamp"`
	CreationDate         int64  `json:"creation_date"`
	LastModificationDate int64  `json:"last_modification_date"`
}

// ListAgentGroups retrieves all agent groups.
func (c *Client) ListAgentGroups(ctx context.Context) ([]AgentGroup, error) {
	var resp apiAgentGroupList
	if err := c.getJSON(ctx, "/agent-groups", &resp); err != nil {
		return nil, err
	}

	groups := make([]AgentGroup, len(resp.Groups))
	for i, g := range resp.Groups {
		groups[i] = AgentGroup(g)
	}
	return groups, nil
}
