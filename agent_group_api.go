package nessus

import "context"

type apiAgentGroupList struct {
	Groups []apiAgentGroup `json:"groups"`
}

type apiAgentGroup struct {
	ID                   int    `json:"id"`
	Name                 string `json:"name"`
	AgentsCount          int    `json:"agents_count"`
	OwnerID              int    `json:"owner_id"`
	OwnerName            string `json:"owner_name"`
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
		groups[i] = AgentGroup{
			ID:                   g.ID,
			Name:                 g.Name,
			AgentsCount:          g.AgentsCount,
			OwnerID:              g.OwnerID,
			OwnerName:            g.OwnerName,
			CreationDate:         g.CreationDate,
			LastModificationDate: g.LastModificationDate,
		}
	}
	return groups, nil
}
