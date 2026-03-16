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
	Output string              `json:"plugin_output"`
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
	PluginID       any                    `json:"pluginid"`
	Name           string                 `json:"pluginname"`
	Family         string                 `json:"pluginfamily"`
	Severity       any                    `json:"severity"`
	PluginAttrs    apiPluginAttrs         `json:"pluginattributes"`
}

type apiPluginAttrs struct {
	Synopsis       string  `json:"synopsis"`
	Description    string  `json:"description"`
	Solution       string  `json:"solution"`
	SeeAlso        any     `json:"see_also"`
	RiskFactor     string  `json:"risk_factor"`
	CVSSVector     string  `json:"cvss_vector"`
	CVSSBaseScore  string  `json:"cvss_base_score"`
	CVSS3Vector    string  `json:"cvss3_vector"`
	CVSS3BaseScore string  `json:"cvss3_base_score"`
	RefInfo        apiRefInfo `json:"ref_information"`
}

type apiRefInfo struct {
	Refs []apiRef `json:"ref"`
}

type apiRef struct {
	Name   string      `json:"name"`
	Values []apiRefVal `json:"value"`
}

type apiRefVal struct {
	Value string `json:"value"`
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
			if _, ok := result.Ports[port]; !ok {
				result.Ports[port] = nil
			}
			for _, p := range infos {
				result.Ports[port] = append(result.Ports[port], PortInfo{
					Port:   p.Port,
					Output: p.Output,
				})
			}
		}
	}

	// Extract plugin info.
	d := resp.Info.PluginDetails
	a := d.PluginAttrs

	var cves, bids, xrefs []string
	for _, ref := range a.RefInfo.Refs {
		vals := make([]string, len(ref.Values))
		for i, v := range ref.Values {
			vals[i] = v.Value
		}
		switch ref.Name {
		case "cve":
			cves = vals
		case "bid":
			bids = vals
		default:
			for _, v := range vals {
				xrefs = append(xrefs, ref.Name+":"+v)
			}
		}
	}

	result.Info = PluginInfo{
		PluginID:       toInt(d.PluginID),
		Name:           d.Name,
		Family:         d.Family,
		Severity:       toInt(d.Severity),
		Synopsis:       a.Synopsis,
		Description:    a.Description,
		Solution:       a.Solution,
		SeeAlso:        toSeeAlso(a.SeeAlso),
		RiskFactor:     a.RiskFactor,
		CVE:            cves,
		BID:            bids,
		XREF:           xrefs,
		CVSSVector:     a.CVSSVector,
		CVSSBaseScore:  parseFloat(a.CVSSBaseScore),
		CVSS3Vector:    a.CVSS3Vector,
		CVSS3BaseScore: parseFloat(a.CVSS3BaseScore),
	}

	return result, nil
}
