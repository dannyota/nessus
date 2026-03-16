package nessus

import "testing"

func TestExtractOS(t *testing.T) {
	t.Run("found in plugin 11936", func(t *testing.T) {
		host := ExportHost{
			Findings: []Finding{
				{PluginID: 22869, Output: "some info"},
				{PluginID: PluginIDOSIdentification, Output: "Remote operating system : Microsoft Windows Server 2019 Standard\nConfidence level : 99\nMethod : SMB_OS"},
			},
		}
		info := ExtractOS(host)
		if info.Name != "Microsoft Windows Server 2019 Standard" {
			t.Errorf("Name = %q", info.Name)
		}
		if info.Family != "windows" {
			t.Errorf("Family = %q", info.Family)
		}
		if info.Confidence != 99 {
			t.Errorf("Confidence = %d", info.Confidence)
		}
	})

	t.Run("falls back to host OS property", func(t *testing.T) {
		host := ExportHost{
			OS: "Linux Kernel 5.15 on Ubuntu 22.04",
			Findings: []Finding{
				{PluginID: 22869, Output: "SSH info"},
			},
		}
		info := ExtractOS(host)
		if info.Name != "Linux Kernel 5.15 on Ubuntu 22.04" {
			t.Errorf("Name = %q", info.Name)
		}
		if info.Family != "linux" {
			t.Errorf("Family = %q", info.Family)
		}
		if info.Confidence != 0 {
			t.Errorf("Confidence = %d, want 0 for fallback", info.Confidence)
		}
	})

	t.Run("multiline host OS uses first line", func(t *testing.T) {
		host := ExportHost{
			OS: "Microsoft Windows Server 2019\nMicrosoft Windows 10",
		}
		info := ExtractOS(host)
		if info.Name != "Microsoft Windows Server 2019" {
			t.Errorf("Name = %q", info.Name)
		}
		if info.Family != "windows" {
			t.Errorf("Family = %q", info.Family)
		}
	})

	t.Run("not found", func(t *testing.T) {
		host := ExportHost{
			Findings: []Finding{
				{PluginID: 22869, Output: "SSH server info"},
			},
		}
		info := ExtractOS(host)
		if info.Name != "" {
			t.Errorf("Name = %q, want empty", info.Name)
		}
	})

	t.Run("empty host", func(t *testing.T) {
		info := ExtractOS(ExportHost{})
		if info.Name != "" {
			t.Errorf("Name = %q, want empty", info.Name)
		}
	})

	t.Run("plugin present but no OS in output", func(t *testing.T) {
		host := ExportHost{
			OS: "Linux Kernel 5.15",
			Findings: []Finding{
				{PluginID: PluginIDOSIdentification, Output: "The remote host could not be identified."},
			},
		}
		info := ExtractOS(host)
		// Should fall back to host OS property
		if info.Name != "Linux Kernel 5.15" {
			t.Errorf("Name = %q", info.Name)
		}
		if info.Family != "linux" {
			t.Errorf("Family = %q", info.Family)
		}
	})
}

func TestParseOS(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantName   string
		wantFamily string
		wantConf   int
	}{
		{
			name:       "windows with confidence",
			output:     "Remote operating system : Microsoft Windows Server 2019 Standard\nConfidence level : 99\nMethod : SMB_OS",
			wantName:   "Microsoft Windows Server 2019 Standard",
			wantFamily: "windows",
			wantConf:   99,
		},
		{
			name:       "linux with confidence",
			output:     "Remote operating system : Linux Kernel 5.15 on Ubuntu 22.04\nConfidence level : 95\nMethod : SSH",
			wantName:   "Linux Kernel 5.15 on Ubuntu 22.04",
			wantFamily: "linux",
			wantConf:   95,
		},
		{
			name:       "no confidence line",
			output:     "Remote operating system : FreeBSD 13.1",
			wantName:   "FreeBSD 13.1",
			wantFamily: "freebsd",
			wantConf:   0,
		},
		{
			name:       "no match",
			output:     "The remote host could not be identified.",
			wantName:   "",
			wantFamily: "",
			wantConf:   0,
		},
		{
			name:       "empty",
			output:     "",
			wantName:   "",
			wantFamily: "",
			wantConf:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ParseOS(tt.output)
			if info.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", info.Name, tt.wantName)
			}
			if info.Family != tt.wantFamily {
				t.Errorf("Family = %q, want %q", info.Family, tt.wantFamily)
			}
			if info.Confidence != tt.wantConf {
				t.Errorf("Confidence = %d, want %d", info.Confidence, tt.wantConf)
			}
		})
	}
}

func TestOSFamily(t *testing.T) {
	tests := []struct {
		os   string
		want string
	}{
		{"Microsoft Windows Server 2019 Standard", "windows"},
		{"Microsoft Windows 10 Enterprise", "windows"},
		{"Windows 11 Pro", "windows"},
		{"Linux Kernel 5.15", "linux"},
		{"Linux Kernel 5.15 on Ubuntu 22.04", "linux"},
		{"Ubuntu 22.04", "linux"},
		{"Debian 11", "linux"},
		{"CentOS 7", "linux"},
		{"Red Hat Enterprise Linux 8", "linux"},
		{"RHEL 9", "linux"},
		{"Amazon Linux 2", "linux"},
		{"Oracle Linux Server 8", "linux"},
		{"SUSE Linux Enterprise Server 15", "linux"},
		{"AlmaLinux 9", "linux"},
		{"Rocky Linux 9", "linux"},
		{"Fedora 38", "linux"},
		{"Mac OS X 12.6", "macos"},
		{"Apple macOS Ventura", "macos"},
		{"Darwin 22.1.0", "macos"},
		{"FreeBSD 13.1", "freebsd"},
		{"OpenBSD 7.2", "openbsd"},
		{"NetBSD 9.3", "netbsd"},
		{"Solaris 11.4", "solaris"},
		{"SunOS 5.11", "solaris"},
		{"AIX 7.2", "aix"},
		{"HP-UX 11.31", "hpux"},
		{"Cisco IOS 15.2", "cisco"},
		{"VMware ESXi 7.0", "vmware"},
		{"JunOS 21.4", "juniper"},
		{"FortiOS 7.2", "fortinet"},
		{"something unknown", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.os, func(t *testing.T) {
			got := OSFamily(tt.os)
			if got != tt.want {
				t.Errorf("OSFamily(%q) = %q, want %q", tt.os, got, tt.want)
			}
		})
	}
}
