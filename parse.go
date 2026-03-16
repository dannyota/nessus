package nessus

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// XML structures for Nessus export format.

type xmlNessusClientData struct {
	Report xmlReport `xml:"Report"`
}

type xmlReport struct {
	Name  string          `xml:"name,attr"`
	Hosts []xmlReportHost `xml:"ReportHost"`
}

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

	Synopsis     string   `xml:"synopsis"`
	Description  string   `xml:"description"`
	Solution     string   `xml:"solution"`
	PluginOutput string   `xml:"plugin_output"`
	SeeAlso      string   `xml:"see_also"`
	RiskFactor   string   `xml:"risk_factor"`

	CVSSBaseScore  string `xml:"cvss_base_score"`
	CVSSVector     string `xml:"cvss_vector"`
	CVSS3BaseScore string `xml:"cvss3_base_score"`
	CVSS3Vector    string `xml:"cvss3_vector"`

	CVE  []string `xml:"cve"`
	BID  []string `xml:"bid"`
	XREF []string `xml:"xref"`
}

// ParseNessusXML parses a Nessus XML export into structured types.
// The result contains the same data as calling GetHostDetails + GetPluginOutput
// for every host, but from a single bulk download.
func ParseNessusXML(data []byte) (*ExportResult, error) {
	var doc xmlNessusClientData
	if err := xml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("nessus: parse XML: %w", err)
	}

	result := &ExportResult{
		Name:  doc.Report.Name,
		Hosts: make([]ExportHost, 0, len(doc.Report.Hosts)),
	}

	for _, h := range doc.Report.Hosts {
		host := convertXMLHost(h)
		result.Hosts = append(result.Hosts, host)
	}

	return result, nil
}

func convertXMLHost(h xmlReportHost) ExportHost {
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
		}
	}

	host.Findings = make([]Finding, 0, len(h.ReportItems))
	for _, item := range h.ReportItems {
		host.Findings = append(host.Findings, convertXMLReportItem(item))
	}

	return host
}

func convertXMLReportItem(item xmlReportItem) Finding {
	pluginID, _ := strconv.Atoi(item.PluginID)
	severity, _ := strconv.Atoi(item.Severity)

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
		SeeAlso:     item.SeeAlso,
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

	// Normalize see_also: split on newlines if it contains multiple URLs.
	f.SeeAlso = strings.TrimSpace(f.SeeAlso)

	return f
}
