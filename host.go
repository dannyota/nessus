package nessus

import (
	"context"
	"fmt"
)

type apiHostDetail struct {
	Info            apiHostInfo            `json:"info"`
	Vulnerabilities []apiHostVulnerability `json:"vulnerabilities"`
}

type apiHostInfo struct {
	HostIP   string `json:"host-ip"`
	HostFQDN string `json:"host-fqdn"`
	OS       string `json:"operating-system"`
}

type apiHostVulnerability struct {
	PluginID     int    `json:"plugin_id"`
	PluginName   string `json:"plugin_name"`
	PluginFamily string `json:"plugin_family"`
	Severity     int    `json:"severity"`
	Count        int    `json:"count"`
}

// GetHostDetails retrieves the vulnerability list for a specific host in a scan.
func (c *Client) GetHostDetails(ctx context.Context, scanID, hostID int) ([]HostVulnerability, error) {
	var resp apiHostDetail
	if err := c.getJSON(ctx, fmt.Sprintf("/scans/%d/hosts/%d", scanID, hostID), &resp); err != nil {
		return nil, err
	}

	vulns := make([]HostVulnerability, len(resp.Vulnerabilities))
	for i, v := range resp.Vulnerabilities {
		vulns[i] = HostVulnerability{
			PluginID:     v.PluginID,
			PluginName:   v.PluginName,
			PluginFamily: v.PluginFamily,
			Severity:     v.Severity,
			Count:        v.Count,
		}
	}

	return vulns, nil
}
