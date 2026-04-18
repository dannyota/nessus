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
	HostIP      string `json:"host-ip"`
	HostFQDN    string `json:"host-fqdn"`
	Hostname    string `json:"hostname"`
	OS          string `json:"operating-system"`
	MACAddress  string `json:"mac-address"`
	NetBIOSName string `json:"netbios-name"`
}

type apiHostVulnerability struct {
	PluginID     int    `json:"plugin_id"`
	PluginName   string `json:"plugin_name"`
	PluginFamily string `json:"plugin_family"`
	Severity     int    `json:"severity"`
	Count        int    `json:"count"`
}

// GetHostDetails retrieves host info and the vulnerability list for a specific host in a scan.
func (c *Client) GetHostDetails(ctx context.Context, scanID, hostID int) (*ScanHostDetail, error) {
	var resp apiHostDetail
	if err := c.getJSON(ctx, fmt.Sprintf("/scans/%d/hosts/%d", scanID, hostID), &resp); err != nil {
		return nil, err
	}

	detail := &ScanHostDetail{
		IP:          resp.Info.HostIP,
		FQDN:        resp.Info.HostFQDN,
		Hostname:    resp.Info.Hostname,
		OS:          resp.Info.OS,
		MAC:         resp.Info.MACAddress,
		NetBIOSName: resp.Info.NetBIOSName,
	}

	detail.Vulnerabilities = make([]ScanHostVulnerability, len(resp.Vulnerabilities))
	for i, v := range resp.Vulnerabilities {
		detail.Vulnerabilities[i] = ScanHostVulnerability(v)
	}

	return detail, nil
}
