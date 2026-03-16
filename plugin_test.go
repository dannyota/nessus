package nessus

import (
	"context"
	"testing"
)

func TestGetPluginOutput(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42/hosts/1/plugins/12345": `{
			"outputs": [
				{
					"plugin_output": "The SSL certificate has expired.",
					"ports": {
						"443 / tcp / www": []
					}
				}
			],
			"info": {
				"plugindescription": {
					"pluginid": 12345,
					"pluginname": "SSL Certificate Expired",
					"pluginfamily": "General",
					"severity": 4,
					"pluginattributes": {
						"plugin_name": "SSL Certificate Expired",
						"synopsis": "The remote SSL certificate has expired.",
						"description": "The X.509 certificate chain used by this service has expired.",
						"solution": "Purchase or generate a new SSL certificate.",
						"see_also": "https://example.com/docs",
						"risk_information": {
							"risk_factor": "Critical",
							"cvss_vector": "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N",
							"cvss_base_score": "5.0",
							"cvss3_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
							"cvss3_base_score": "5.3"
						},
						"ref_information": {
							"ref": [
								{
									"name": "cve",
									"values": {
										"value": ["CVE-2023-1234", "CVE-2023-5678"]
									}
								},
								{
									"name": "bid",
									"values": {
										"value": ["12345"]
									}
								},
								{
									"name": "cwe",
									"values": {
										"value": ["295"]
									}
								}
							]
						}
					}
				}
			}
		}`,
	})

	result, err := client.GetPluginOutput(context.Background(), 42, 1, 12345)
	if err != nil {
		t.Fatal(err)
	}

	if result.Output != "The SSL certificate has expired." {
		t.Errorf("Output = %q", result.Output)
	}

	if len(result.Ports) != 0 {
		t.Errorf("Ports = %v, want empty (no port entries in fixture)", result.Ports)
	}

	info := result.Info
	if info.PluginID != 12345 {
		t.Errorf("PluginID = %d", info.PluginID)
	}
	if info.Name != "SSL Certificate Expired" {
		t.Errorf("Name = %q", info.Name)
	}
	if info.Synopsis != "The remote SSL certificate has expired." {
		t.Errorf("Synopsis = %q", info.Synopsis)
	}
	if info.Solution != "Purchase or generate a new SSL certificate." {
		t.Errorf("Solution = %q", info.Solution)
	}
	if info.RiskFactor != "Critical" {
		t.Errorf("RiskFactor = %q", info.RiskFactor)
	}
	if info.CVSSBaseScore != 5.0 {
		t.Errorf("CVSSBaseScore = %f", info.CVSSBaseScore)
	}
	if info.CVSS3BaseScore != 5.3 {
		t.Errorf("CVSS3BaseScore = %f", info.CVSS3BaseScore)
	}
	if info.CVSSVector != "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N" {
		t.Errorf("CVSSVector = %q", info.CVSSVector)
	}
	if len(info.CVE) != 2 {
		t.Fatalf("len(CVE) = %d, want 2", len(info.CVE))
	}
	if info.CVE[0] != "CVE-2023-1234" {
		t.Errorf("CVE[0] = %q", info.CVE[0])
	}
	if len(info.BID) != 1 {
		t.Fatalf("len(BID) = %d, want 1", len(info.BID))
	}
	if len(info.XREF) != 1 || info.XREF[0] != "cwe:295" {
		t.Errorf("XREF = %v, want [cwe:295]", info.XREF)
	}
	if len(info.SeeAlso) != 1 || info.SeeAlso[0] != "https://example.com/docs" {
		t.Errorf("SeeAlso = %v", info.SeeAlso)
	}
}

func TestGetPluginOutput_SeeAlsoArray(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42/hosts/1/plugins/99999": `{
			"outputs": [],
			"info": {
				"plugindescription": {
					"pluginid": "99999",
					"pluginname": "",
					"pluginfamily": "Red Hat Local Security Checks",
					"severity": "3",
					"pluginattributes": {
						"plugin_name": "RHEL 9 : example",
						"synopsis": "Missing security update.",
						"description": "Desc.",
						"solution": "Update.",
						"see_also": ["https://example.com/1", "https://example.com/2"],
						"risk_information": {
							"risk_factor": "High",
							"cvss_base_score": "10.0",
							"cvss3_base_score": "8.8"
						},
						"ref_information": {
							"ref": [
								{
									"name": "cve",
									"values": {"value": ["CVE-2025-0001"]}
								}
							]
						}
					}
				}
			}
		}`,
	})

	result, err := client.GetPluginOutput(context.Background(), 42, 1, 99999)
	if err != nil {
		t.Fatal(err)
	}

	if result.Info.PluginID != 99999 {
		t.Errorf("PluginID = %d", result.Info.PluginID)
	}
	if result.Info.Name != "RHEL 9 : example" {
		t.Errorf("Name = %q (should use plugin_name from attrs)", result.Info.Name)
	}
	if result.Info.Severity != SeverityHigh {
		t.Errorf("Severity = %d, want SeverityHigh", result.Info.Severity)
	}
	if result.Info.RiskFactor != "High" {
		t.Errorf("RiskFactor = %q", result.Info.RiskFactor)
	}
	if result.Info.CVSSBaseScore != 10.0 {
		t.Errorf("CVSSBaseScore = %f", result.Info.CVSSBaseScore)
	}
	if result.Info.CVSS3BaseScore != 8.8 {
		t.Errorf("CVSS3BaseScore = %f", result.Info.CVSS3BaseScore)
	}
	if len(result.Info.SeeAlso) != 2 || result.Info.SeeAlso[0] != "https://example.com/1" {
		t.Errorf("SeeAlso = %v", result.Info.SeeAlso)
	}
	if len(result.Info.CVE) != 1 || result.Info.CVE[0] != "CVE-2025-0001" {
		t.Errorf("CVE = %v", result.Info.CVE)
	}
}

func TestGetPluginOutput_NoOutput(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42/hosts/1/plugins/11111": `{
			"outputs": [],
			"info": {
				"plugindescription": {
					"pluginid": 11111,
					"pluginname": "Info Plugin",
					"pluginfamily": "General",
					"severity": 0,
					"pluginattributes": {
						"synopsis": "Informational.",
						"description": "This is informational.",
						"solution": "n/a",
						"risk_information": {
							"risk_factor": "None"
						},
						"ref_information": {"ref": []}
					}
				}
			}
		}`,
	})

	result, err := client.GetPluginOutput(context.Background(), 42, 1, 11111)
	if err != nil {
		t.Fatal(err)
	}

	if result.Output != "" {
		t.Errorf("Output = %q, want empty", result.Output)
	}
	if result.Info.Severity != SeverityInfo {
		t.Errorf("Severity = %d, want SeverityInfo", result.Info.Severity)
	}
	if result.Info.RiskFactor != "None" {
		t.Errorf("RiskFactor = %q", result.Info.RiskFactor)
	}
}
