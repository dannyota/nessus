package nessus

import "testing"

const testXML = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Weekly Scan">
    <ReportHost name="192.168.1.10">
      <HostProperties>
        <tag name="host-ip">192.168.1.10</tag>
        <tag name="host-fqdn">web-01.example.com</tag>
        <tag name="operating-system">Linux 5.15</tag>
        <tag name="mac-address">AA:BB:CC:DD:EE:FF</tag>
      </HostProperties>
      <ReportItem pluginID="279708" pluginName="RHEL 9 : webkit2gtk3 (RHSA-2025:23974)" pluginFamily="Red Hat Local Security Checks" severity="3" port="0" protocol="tcp" svc_name="general">
        <synopsis>The remote Red Hat host is missing one or more security updates.</synopsis>
        <description>The remote host has packages that are affected by multiple vulnerabilities.</description>
        <solution>Update the RHEL webkit2gtk3 package based on the guidance in RHSA-2025:23974.</solution>
        <plugin_output>Remote package installed : webkit2gtk3-jsc-2.50.1-0.el9_6
Should be                : webkit2gtk3-jsc-2.50.4-1.el9_6</plugin_output>
        <see_also>https://access.redhat.com/errata/RHSA-2025:23974</see_also>
        <risk_factor>Critical</risk_factor>
        <cvss_base_score>10.0</cvss_base_score>
        <cvss_vector>CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C</cvss_vector>
        <cvss3_base_score>8.8</cvss3_base_score>
        <cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</cvss3_vector>
        <cve>CVE-2025-43501</cve>
        <cve>CVE-2025-43529</cve>
        <xref>RHSA:2025:23974</xref>
      </ReportItem>
      <ReportItem pluginID="22869" pluginName="Software Enumeration (SSH)" pluginFamily="General" severity="0" port="22" protocol="tcp" svc_name="ssh">
        <synopsis>Enumerates software installed on the remote host.</synopsis>
        <description>Detects installed software via SSH.</description>
        <solution>n/a</solution>
        <risk_factor>None</risk_factor>
      </ReportItem>
    </ReportHost>
    <ReportHost name="192.168.1.20">
      <HostProperties>
        <tag name="host-ip">192.168.1.20</tag>
        <tag name="host-fqdn">db-01.example.com</tag>
        <tag name="operating-system">Ubuntu 22.04</tag>
      </HostProperties>
      <ReportItem pluginID="10881" pluginName="SSH Protocol Versions Supported" pluginFamily="General" severity="0" port="22" protocol="tcp" svc_name="ssh">
        <synopsis>SSH server supports SSHv2.</synopsis>
        <description>The remote SSH server supports the following protocol versions.</description>
        <solution>n/a</solution>
        <risk_factor>None</risk_factor>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func TestParseNessusXML(t *testing.T) {
	result, err := ParseNessusXML([]byte(testXML))
	if err != nil {
		t.Fatal(err)
	}

	if result.Name != "Weekly Scan" {
		t.Errorf("Name = %q", result.Name)
	}
	if len(result.Hosts) != 2 {
		t.Fatalf("len(Hosts) = %d, want 2", len(result.Hosts))
	}

	// First host.
	h := result.Hosts[0]
	if h.IP != "192.168.1.10" {
		t.Errorf("IP = %q", h.IP)
	}
	if h.FQDN != "web-01.example.com" {
		t.Errorf("FQDN = %q", h.FQDN)
	}
	if h.OS != "Linux 5.15" {
		t.Errorf("OS = %q", h.OS)
	}
	if h.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC = %q", h.MAC)
	}
	if len(h.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(h.Findings))
	}

	// Critical finding with full details.
	f := h.Findings[0]
	if f.PluginID != 279708 {
		t.Errorf("PluginID = %d", f.PluginID)
	}
	if f.PluginName != "RHEL 9 : webkit2gtk3 (RHSA-2025:23974)" {
		t.Errorf("PluginName = %q", f.PluginName)
	}
	if f.Severity != 3 {
		t.Errorf("Severity = %d", f.Severity)
	}
	if f.Port != "0" {
		t.Errorf("Port = %q", f.Port)
	}
	if f.Protocol != "tcp" {
		t.Errorf("Protocol = %q", f.Protocol)
	}
	if f.Synopsis != "The remote Red Hat host is missing one or more security updates." {
		t.Errorf("Synopsis = %q", f.Synopsis)
	}
	if f.Solution != "Update the RHEL webkit2gtk3 package based on the guidance in RHSA-2025:23974." {
		t.Errorf("Solution = %q", f.Solution)
	}
	if f.RiskFactor != "Critical" {
		t.Errorf("RiskFactor = %q", f.RiskFactor)
	}
	if f.CVSSBaseScore != 10.0 {
		t.Errorf("CVSSBaseScore = %f", f.CVSSBaseScore)
	}
	if f.CVSS3BaseScore != 8.8 {
		t.Errorf("CVSS3BaseScore = %f", f.CVSS3BaseScore)
	}
	if f.CVSSVector != "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" {
		t.Errorf("CVSSVector = %q", f.CVSSVector)
	}

	// Evidence text.
	if f.Output == "" {
		t.Error("Output is empty")
	}
	if f.Output != "Remote package installed : webkit2gtk3-jsc-2.50.1-0.el9_6\nShould be                : webkit2gtk3-jsc-2.50.4-1.el9_6" {
		t.Errorf("Output = %q", f.Output)
	}

	// CVEs.
	if len(f.CVE) != 2 {
		t.Fatalf("len(CVE) = %d, want 2", len(f.CVE))
	}
	if f.CVE[0] != "CVE-2025-43501" {
		t.Errorf("CVE[0] = %q", f.CVE[0])
	}
	if f.CVE[1] != "CVE-2025-43529" {
		t.Errorf("CVE[1] = %q", f.CVE[1])
	}

	// XREFs.
	if len(f.XREF) != 1 || f.XREF[0] != "RHSA:2025:23974" {
		t.Errorf("XREF = %v", f.XREF)
	}

	// Info-level finding.
	f2 := h.Findings[1]
	if f2.Severity != 0 {
		t.Errorf("Severity = %d, want 0", f2.Severity)
	}
	if f2.Port != "22" {
		t.Errorf("Port = %q", f2.Port)
	}
	if f2.Service != "ssh" {
		t.Errorf("Service = %q", f2.Service)
	}

	// Second host.
	h2 := result.Hosts[1]
	if h2.IP != "192.168.1.20" {
		t.Errorf("IP = %q", h2.IP)
	}
	if h2.OS != "Ubuntu 22.04" {
		t.Errorf("OS = %q", h2.OS)
	}
	if len(h2.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(h2.Findings))
	}
}

func TestParseNessusXML_Empty(t *testing.T) {
	xml := `<?xml version="1.0"?><NessusClientData_v2><Report name="Empty Scan"></Report></NessusClientData_v2>`
	result, err := ParseNessusXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "Empty Scan" {
		t.Errorf("Name = %q", result.Name)
	}
	if len(result.Hosts) != 0 {
		t.Errorf("len(Hosts) = %d, want 0", len(result.Hosts))
	}
}

func TestParseNessusXML_Invalid(t *testing.T) {
	_, err := ParseNessusXML([]byte("not xml"))
	if err == nil {
		t.Fatal("expected error")
	}
}
