package nessus

import (
	"context"
	"fmt"
)

type apiPluginOutput struct {
	Outputs []apiPluginOutputEntry `json:"outputs"`
	Info    apiPluginInfo          `json:"info"`
}

type apiPluginOutputEntry struct {
	Output string               `json:"plugin_output"`
	Ports  map[string][]apiPort `json:"ports"`
}

type apiPort struct {
	Port   string `json:"port"`
	Output string `json:"output"`
}

type apiPluginInfo struct {
	PluginDetails apiPluginDetails `json:"plugindescription"`
}

type apiPluginDetails struct {
	PluginID    any            `json:"pluginid"`
	Name        string         `json:"pluginname"`
	Family      string         `json:"pluginfamily"`
	Severity    any            `json:"severity"`
	PluginAttrs apiPluginAttrs `json:"pluginattributes"`
}

type apiPluginAttrs struct {
	PluginName  string      `json:"plugin_name"`
	Synopsis    string      `json:"synopsis"`
	Description string      `json:"description"`
	Solution    string      `json:"solution"`
	SeeAlso     any         `json:"see_also"`
	RiskInfo    apiRiskInfo `json:"risk_information"`
	RefInfo     apiRefInfo  `json:"ref_information"`
}

type apiRiskInfo struct {
	RiskFactor     string `json:"risk_factor"`
	CVSSVector     string `json:"cvss_vector"`
	CVSSBaseScore  string `json:"cvss_base_score"`
	CVSS3Vector    string `json:"cvss3_vector"`
	CVSS3BaseScore string `json:"cvss3_base_score"`
}

type apiRefInfo struct {
	Refs []apiRef `json:"ref"`
}

type apiRef struct {
	Name   string       `json:"name"`
	Values apiRefValues `json:"values"`
}

type apiRefValues struct {
	Value []string `json:"value"`
}

// GetPluginOutput retrieves detailed finding output for a specific plugin on a host.
func (c *Client) GetPluginOutput(ctx context.Context, scanID, hostID, pluginID int) (*PluginOutput, error) {
	var resp apiPluginOutput
	if err := c.getJSON(ctx, fmt.Sprintf("/scans/%d/hosts/%d/plugins/%d", scanID, hostID, pluginID), &resp); err != nil {
		return nil, err
	}

	result := &PluginOutput{
		Ports: make(map[string][]PortInfo),
	}

	// Combine output from all entries.
	for _, entry := range resp.Outputs {
		if entry.Output != "" {
			if result.Output != "" {
				result.Output += "\n\n"
			}
			result.Output += entry.Output
		}
		for port, infos := range entry.Ports {
			for _, p := range infos {
				result.Ports[port] = append(result.Ports[port], PortInfo(p))
			}
		}
	}

	// Extract plugin info.
	d := resp.Info.PluginDetails
	a := d.PluginAttrs
	r := a.RiskInfo

	// Plugin name: prefer pluginattributes.plugin_name, fall back to top-level pluginname.
	name := a.PluginName
	if name == "" {
		name = d.Name
	}

	var cves, bids, xrefs []string
	for _, ref := range a.RefInfo.Refs {
		switch ref.Name {
		case "cve":
			cves = ref.Values.Value
		case "bid":
			bids = ref.Values.Value
		default:
			for _, v := range ref.Values.Value {
				xrefs = append(xrefs, ref.Name+":"+v)
			}
		}
	}

	result.Info = PluginInfo{
		PluginID:       toInt(d.PluginID),
		Name:           name,
		Family:         d.Family,
		Severity:       toInt(d.Severity),
		Synopsis:       a.Synopsis,
		Description:    a.Description,
		Solution:       a.Solution,
		SeeAlso:        toSeeAlso(a.SeeAlso),
		RiskFactor:     r.RiskFactor,
		CVE:            cves,
		BID:            bids,
		XREF:           xrefs,
		CVSSVector:     r.CVSSVector,
		CVSSBaseScore:  parseFloat(r.CVSSBaseScore),
		CVSS3Vector:    r.CVSS3Vector,
		CVSS3BaseScore: parseFloat(r.CVSS3BaseScore),
	}

	return result, nil
}
