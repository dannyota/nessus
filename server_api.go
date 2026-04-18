package nessus

import "context"

type apiServerProperties struct {
	NessusType  string     `json:"nessus_type"`
	ServerUUID  string     `json:"server_uuid"`
	NessusUIVer string     `json:"nessus_ui_version"`
	Platform    string     `json:"platform"`
	PluginSet   string     `json:"plugin_set"`
	Expiration  int64      `json:"expiration"`
	License     apiLicense `json:"license"`
}

type apiLicense struct {
	Type         string `json:"type"`
	IPs          int    `json:"ips"`
	Agents       int    `json:"agents"`
	AgentsUsed   int    `json:"agents_used"`
	Scanners     int    `json:"scanners"`
	ScannersUsed int    `json:"scanners_used"`
}

// ServerProperties returns metadata about the Nessus Manager instance.
func (c *Client) ServerProperties(ctx context.Context) (*ServerInfo, error) {
	var resp apiServerProperties
	if err := c.getJSON(ctx, "/server/properties", &resp); err != nil {
		return nil, err
	}

	return &ServerInfo{
		NessusType:       resp.NessusType,
		ServerUUID:       resp.ServerUUID,
		Version:          resp.NessusUIVer,
		Platform:         resp.Platform,
		PluginSet:        resp.PluginSet,
		LicenseType:      resp.License.Type,
		LicenseExpiry:    resp.Expiration,
		LicensedHosts:    resp.License.IPs,
		LicensedAgents:   resp.License.Agents,
		AgentsUsed:       resp.License.AgentsUsed,
		LicensedScanners: resp.License.Scanners,
		ScannersUsed:     resp.License.ScannersUsed,
	}, nil
}
