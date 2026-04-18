package nessus

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// XML structures for Nessus export format (used by streaming parser).

type xmlReportHost struct {
	Name           string            `xml:"name,attr"`
	HostProperties []xmlHostProperty `xml:"HostProperties>tag"`
	ReportItems    []xmlReportItem   `xml:"ReportItem"`
}

type xmlHostProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type xmlReportItem struct {
	PluginID     string `xml:"pluginID,attr"`
	PluginName   string `xml:"pluginName,attr"`
	PluginFamily string `xml:"pluginFamily,attr"`
	Severity     string `xml:"severity,attr"`
	Port         string `xml:"port,attr"`
	Protocol     string `xml:"protocol,attr"`
	SvcName      string `xml:"svc_name,attr"`

	Synopsis     string `xml:"synopsis"`
	Description  string `xml:"description"`
	Solution     string `xml:"solution"`
	PluginOutput string `xml:"plugin_output"`
	SeeAlso      string `xml:"see_also"`
	RiskFactor   string `xml:"risk_factor"`

	CVSSBaseScore  string `xml:"cvss_base_score"`
	CVSSVector     string `xml:"cvss_vector"`
	CVSS3BaseScore string `xml:"cvss3_base_score"`
	CVSS3Vector    string `xml:"cvss3_vector"`

	CVE  []string `xml:"cve"`
	BID  []string `xml:"bid"`
	XREF []string `xml:"xref"`
}

// ParseNessusXML parses a Nessus XML export into structured types.
// Uses a streaming parser — only one ReportHost is in memory at a time.
//
// Use minSeverity to filter findings: 0=all, 1=low+, 2=medium+, 3=high+, 4=critical only.
func ParseNessusXML(data []byte, minSeverity ...int) (*ExportResult, error) {
	return ParseNessusXMLFromReader(bytes.NewReader(data), minSeverity...)
}

// ParseNessusXMLFromReader parses a Nessus XML export from an io.Reader.
// Uses a streaming parser — only one ReportHost is in memory at a time,
// making it suitable for large exports.
//
// Use minSeverity to filter findings: 0=all, 1=low+, 2=medium+, 3=high+, 4=critical only.
func ParseNessusXMLFromReader(r io.Reader, minSeverity ...int) (*ExportResult, error) {
	minSev := 0
	if len(minSeverity) > 0 {
		minSev = minSeverity[0]
	}

	decoder := xml.NewDecoder(r)
	result := &ExportResult{}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("nessus: parse XML: %w", err)
		}

		elem, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		switch elem.Name.Local {
		case "Report":
			for _, attr := range elem.Attr {
				if attr.Name.Local == "name" {
					result.Name = attr.Value
				}
			}

		case "ReportHost":
			var hostXML xmlReportHost
			if err := decoder.DecodeElement(&hostXML, &elem); err != nil {
				return nil, fmt.Errorf("nessus: parse ReportHost: %w", err)
			}
			result.Hosts = append(result.Hosts, convertXMLHost(hostXML, minSev))
		}
	}

	return result, nil
}

func convertXMLHost(h xmlReportHost, minSeverity int) ExportHost {
	host := ExportHost{
		Hostname: h.Name,
	}

	for _, prop := range h.HostProperties {
		switch prop.Name {
		case "host-ip":
			host.IP = prop.Value
		case "host-fqdn":
			host.FQDN = prop.Value
		case "operating-system":
			host.OS = prop.Value
		case "mac-address":
			host.MAC = prop.Value
		case "netbios-name":
			host.NetBIOSName = prop.Value
		case "HOST_START_TIMESTAMP":
			host.StartTimestamp, _ = strconv.ParseInt(prop.Value, 10, 64)
		case "HOST_END_TIMESTAMP":
			host.EndTimestamp, _ = strconv.ParseInt(prop.Value, 10, 64)
		}
	}

	host.Findings = make([]Finding, 0, len(h.ReportItems))
	for _, item := range h.ReportItems {
		severity, _ := strconv.Atoi(item.Severity)
		if severity < minSeverity {
			continue
		}
		host.Findings = append(host.Findings, convertXMLReportItem(item, severity))
	}

	return host
}

func convertXMLReportItem(item xmlReportItem, severity int) Finding {
	pluginID, _ := strconv.Atoi(item.PluginID)

	f := Finding{
		PluginID:     pluginID,
		PluginName:   item.PluginName,
		PluginFamily: item.PluginFamily,
		Severity:     severity,
		Port:         item.Port,
		Protocol:     item.Protocol,
		Service:      item.SvcName,

		Synopsis:    item.Synopsis,
		Description: item.Description,
		Solution:    item.Solution,
		SeeAlso:     splitSeeAlso(item.SeeAlso),
		RiskFactor:  item.RiskFactor,
		Output:      item.PluginOutput,

		CVSSBaseScore:  parseFloat(item.CVSSBaseScore),
		CVSSVector:     item.CVSSVector,
		CVSS3BaseScore: parseFloat(item.CVSS3BaseScore),
		CVSS3Vector:    item.CVSS3Vector,
	}

	if len(item.CVE) > 0 {
		f.CVE = item.CVE
	}
	if len(item.BID) > 0 {
		f.BID = item.BID
	}
	if len(item.XREF) > 0 {
		f.XREF = item.XREF
	}

	return f
}
