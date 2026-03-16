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
						"synopsis": "The remote SSL certificate has expired.",
						"description": "The X.509 certificate chain used by this service has expired.",
						"solution": "Purchase or generate a new SSL certificate.",
						"see_also": "https://example.com/docs",
						"risk_factor": "Critical",
						"cvss_vector": "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N",
						"cvss_base_score": "5.0",
						"cvss3_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
						"cvss3_base_score": "5.3",
						"ref_information": {
							"ref": [
								{
									"name": "cve",
									"value": [
										{"value": "CVE-2023-1234"},
										{"value": "CVE-2023-5678"}
									]
								},
								{
									"name": "bid",
									"value": [
										{"value": "12345"}
									]
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

	if _, ok := result.Ports["443 / tcp / www"]; !ok {
		t.Error("missing port 443 / tcp / www")
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
	if len(info.CVE) != 2 {
		t.Fatalf("len(CVE) = %d, want 2", len(info.CVE))
	}
	if info.CVE[0] != "CVE-2023-1234" {
		t.Errorf("CVE[0] = %q", info.CVE[0])
	}
	if len(info.BID) != 1 {
		t.Fatalf("len(BID) = %d, want 1", len(info.BID))
	}
}

func TestGetPluginOutput_NoOutput(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/scans/42/hosts/1/plugins/99999": `{
			"outputs": [],
			"info": {
				"plugindescription": {
					"pluginid": 99999,
					"pluginname": "Info Plugin",
					"pluginfamily": "General",
					"severity": 0,
					"pluginattributes": {
						"synopsis": "Informational.",
						"description": "This is informational.",
						"solution": "n/a",
						"risk_factor": "None",
						"ref_information": {"ref": []}
					}
				}
			}
		}`,
	})

	result, err := client.GetPluginOutput(context.Background(), 42, 1, 99999)
	if err != nil {
		t.Fatal(err)
	}

	if result.Output != "" {
		t.Errorf("Output = %q, want empty", result.Output)
	}
	if result.Info.Severity != 0 {
		t.Errorf("Severity = %d, want 0", result.Info.Severity)
	}
	if result.Info.RiskFactor != "None" {
		t.Errorf("RiskFactor = %q", result.Info.RiskFactor)
	}
}
