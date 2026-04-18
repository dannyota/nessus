package nessus

import "context"

type apiPolicyList struct {
	Policies []apiPolicy `json:"policies"`
}

type apiPolicy struct {
	ID                   int    `json:"id"`
	Name                 string `json:"name"`
	Description          string `json:"description"`
	Owner                string `json:"owner"`
	OwnerID              int    `json:"owner_id"`
	Visibility           string `json:"visibility"`
	Shared               int    `json:"shared"`
	UserPermissions      int    `json:"user_permissions"`
	TemplateUUID         string `json:"template_uuid"`
	IsAgent              bool   `json:"is_agent"`
	IsSCAP               int    `json:"is_scap"`
	HasCredentials       int    `json:"has_credentials"`
	NoTarget             string `json:"no_target"`
	CreationDate         int64  `json:"creation_date"`
	LastModificationDate int64  `json:"last_modification_date"`
}

// ListPolicies retrieves all scan policy summaries.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	var resp apiPolicyList
	if err := c.getJSON(ctx, "/policies", &resp); err != nil {
		return nil, err
	}

	policies := make([]Policy, len(resp.Policies))
	for i, p := range resp.Policies {
		policies[i] = Policy(p)
	}
	return policies, nil
}
