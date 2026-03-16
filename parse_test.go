package nessus

import (
	"strings"
	"testing"
)

const testXML = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="host-ip">10.0.0.1</tag>
        <tag name="host-fqdn">web.test.local</tag>
        <tag name="operating-system">Linux 5.15</tag>
        <tag name="mac-address">AA:BB:CC:DD:EE:FF</tag>
        <tag name="netbios-name">WEB01</tag>
        <tag name="HOST_START_TIMESTAMP">1700000000</tag>
        <tag name="HOST_END_TIMESTAMP">1700003600</tag>
      </HostProperties>
      <ReportItem pluginID="10001" pluginName="Example Vuln" pluginFamily="General" severity="3" port="0" protocol="tcp" svc_name="general">
        <synopsis>An example vulnerability was found.</synopsis>
        <description>The host is affected by an example vulnerability.</description>
        <solution>Apply the vendor patch.</solution>
        <plugin_output>Installed: 1.0.0
Fixed: 1.0.1</plugin_output>
        <see_also>https://example.com/advisory/1
https://example.com/advisory/2</see_also>
        <risk_factor>High</risk_factor>
        <cvss_base_score>10.0</cvss_base_score>
        <cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C</cvss_vector>
        <cvss3_base_score>8.8</cvss3_base_score>
        <cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</cvss3_vector>
        <cve>CVE-2024-0001</cve>
        <cve>CVE-2024-0002</cve>
        <xref>VENDOR:12345</xref>
      </ReportItem>
      <ReportItem pluginID="10002" pluginName="SSH Info" pluginFamily="General" severity="0" port="22" protocol="tcp" svc_name="ssh">
        <synopsis>SSH server information.</synopsis>
        <description>Detects SSH version.</description>
        <solution>n/a</solution>
        <risk_factor>None</risk_factor>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.2">
      <HostProperties>
        <tag name="host-ip">10.0.0.2</tag>
        <tag name="host-fqdn">db.test.local</tag>
        <tag name="operating-system">Ubuntu 22.04</tag>
      </HostProperties>
      <ReportItem pluginID="10003" pluginName="Low Finding" pluginFamily="Misc." severity="1" port="443" protocol="tcp" svc_name="www">
        <synopsis>A low severity finding.</synopsis>
        <description>Something minor.</description>
        <solution>Consider updating.</solution>
        <risk_factor>Low</risk_factor>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func TestParseNessusXML(t *testing.T) {
	result, err := ParseNessusXML([]byte(testXML))
	if err != nil {
		t.Fatal(err)
	}

	if result.Name != "Test Scan" {
		t.Errorf("Name = %q", result.Name)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("len(Hosts) = %d, want 2", len(result.Hosts))
	}

	// First host — full property coverage.
	h := result.Hosts[0]
	if h.IP != "10.0.0.1" {
		t.Errorf("IP = %q", h.IP)
	}
	if h.FQDN != "web.test.local" {
		t.Errorf("FQDN = %q", h.FQDN)
	}
	if h.OS != "Linux 5.15" {
		t.Errorf("OS = %q", h.OS)
	}
	if h.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC = %q", h.MAC)
	}
	if h.NetBIOSName != "WEB01" {
		t.Errorf("NetBIOSName = %q", h.NetBIOSName)
	}
	if h.StartTimestamp != 1700000000 {
		t.Errorf("StartTimestamp = %d", h.StartTimestamp)
	}
	if h.EndTimestamp != 1700003600 {
		t.Errorf("EndTimestamp = %d", h.EndTimestamp)
	}
	if len(h.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(h.Findings))
	}

	// High severity finding with full details.
	f := h.Findings[0]
	if f.PluginID != 10001 {
		t.Errorf("PluginID = %d", f.PluginID)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %d, want SeverityHigh", f.Severity)
	}
	if f.RiskFactor != "High" {
		t.Errorf("RiskFactor = %q", f.RiskFactor)
	}
	if f.CVSSBaseScore != 10.0 {
		t.Errorf("CVSSBaseScore = %f", f.CVSSBaseScore)
	}
	if f.CVSS3BaseScore != 8.8 {
		t.Errorf("CVSS3BaseScore = %f", f.CVSS3BaseScore)
	}
	if f.Output != "Installed: 1.0.0\nFixed: 1.0.1" {
		t.Errorf("Output = %q", f.Output)
	}
	if f.Solution != "Apply the vendor patch." {
		t.Errorf("Solution = %q", f.Solution)
	}

	// SeeAlso as []string.
	if len(f.SeeAlso) != 2 {
		t.Fatalf("len(SeeAlso) = %d, want 2", len(f.SeeAlso))
	}
	if f.SeeAlso[0] != "https://example.com/advisory/1" {
		t.Errorf("SeeAlso[0] = %q", f.SeeAlso[0])
	}

	// CVEs.
	if len(f.CVE) != 2 || f.CVE[0] != "CVE-2024-0001" {
		t.Errorf("CVE = %v", f.CVE)
	}
	if len(f.XREF) != 1 || f.XREF[0] != "VENDOR:12345" {
		t.Errorf("XREF = %v", f.XREF)
	}

	// Info-level finding.
	f2 := h.Findings[1]
	if f2.Severity != SeverityInfo {
		t.Errorf("Severity = %d, want SeverityInfo", f2.Severity)
	}
	if f2.Port != "22" {
		t.Errorf("Port = %q", f2.Port)
	}
	if f2.Service != "ssh" {
		t.Errorf("Service = %q", f2.Service)
	}

	// Second host.
	h2 := result.Hosts[1]
	if h2.IP != "10.0.0.2" {
		t.Errorf("IP = %q", h2.IP)
	}
	if len(h2.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(h2.Findings))
	}
}

func TestParseNessusXML_MinSeverity(t *testing.T) {
	result, err := ParseNessusXML([]byte(testXML), SeverityHigh)
	if err != nil {
		t.Fatal(err)
	}

	// First host: only the severity=3 finding should remain.
	h := result.Hosts[0]
	if len(h.Findings) != 1 {
		t.Fatalf("host 1: len(Findings) = %d, want 1", len(h.Findings))
	}
	if h.Findings[0].Severity != SeverityHigh {
		t.Errorf("Severity = %d, want SeverityHigh", h.Findings[0].Severity)
	}

	// Second host: severity=1 should be filtered out.
	h2 := result.Hosts[1]
	if len(h2.Findings) != 0 {
		t.Fatalf("host 2: len(Findings) = %d, want 0", len(h2.Findings))
	}
}

func TestParseNessusXML_Empty(t *testing.T) {
	xml := `<?xml version="1.0"?><NessusClientData_v2><Report name="Empty"></Report></NessusClientData_v2>`
	result, err := ParseNessusXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "Empty" {
		t.Errorf("Name = %q", result.Name)
	}
	if len(result.Hosts) != 0 {
		t.Errorf("len(Hosts) = %d, want 0", len(result.Hosts))
	}
}

func TestParseNessusXML_Invalid(t *testing.T) {
	_, err := ParseNessusXML([]byte("<broken><xml"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseNessusXMLFromReader(t *testing.T) {
	result, err := ParseNessusXMLFromReader(strings.NewReader(testXML))
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "Test Scan" {
		t.Errorf("Name = %q", result.Name)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("len(Hosts) = %d, want 2", len(result.Hosts))
	}
	if result.Hosts[0].IP != "10.0.0.1" {
		t.Errorf("IP = %q", result.Hosts[0].IP)
	}
	if len(result.Hosts[0].Findings) != 2 {
		t.Errorf("len(Findings) = %d, want 2", len(result.Hosts[0].Findings))
	}
}

func TestParseNessusXMLFromReader_MinSeverity(t *testing.T) {
	result, err := ParseNessusXMLFromReader(strings.NewReader(testXML), SeverityHigh)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts[0].Findings) != 1 {
		t.Fatalf("host 1: len(Findings) = %d, want 1", len(result.Hosts[0].Findings))
	}
	if len(result.Hosts[1].Findings) != 0 {
		t.Fatalf("host 2: len(Findings) = %d, want 0", len(result.Hosts[1].Findings))
	}
}
