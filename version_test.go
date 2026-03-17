package nessus

import "testing"

func TestParseVersions(t *testing.T) {
	t.Run("windows path with single fixed", func(t *testing.T) {
		output := `
  Path              : C:\Program Files (x86)\Microsoft\Edge\Application
  Installed version : 143.0.3650.96
  Fixed version     : 144.0.3719.92
`
		results := ParseVersions(output)
		if len(results) != 1 {
			t.Fatalf("len = %d, want 1", len(results))
		}
		v := results[0]
		if v.Package != `C:\Program Files (x86)\Microsoft\Edge\Application` {
			t.Errorf("Package = %q", v.Package)
		}
		if v.Installed != "143.0.3650.96" {
			t.Errorf("Installed = %q", v.Installed)
		}
		if v.Fixed != "144.0.3719.92" {
			t.Errorf("Fixed = %q", v.Fixed)
		}
	})

	t.Run("windows path with alternative fixed versions", func(t *testing.T) {
		output := `
  Path              : C:\Program Files\Tenable\Nessus Agent
  Installed version : 10.8.2
  Fixed version     : 10.8.5 / 10.9.0
`
		results := ParseVersions(output)
		if len(results) != 1 {
			t.Fatalf("len = %d, want 1", len(results))
		}
		v := results[0]
		if v.Package != `C:\Program Files\Tenable\Nessus Agent` {
			t.Errorf("Package = %q", v.Package)
		}
		if v.Installed != "10.8.2" {
			t.Errorf("Installed = %q", v.Installed)
		}
		if v.Fixed != "10.8.5 / 10.9.0" {
			t.Errorf("Fixed = %q", v.Fixed)
		}
	})

	t.Run("reported version with unix path", func(t *testing.T) {
		output := `
  Path             : /usr/local/openresty/openssl111/lib/libssl.so.1.1
  Reported version : 1.1.1w
  Fixed version    : 1.1.1za
`
		results := ParseVersions(output)
		if len(results) != 1 {
			t.Fatalf("len = %d, want 1", len(results))
		}
		v := results[0]
		if v.Package != "/usr/local/openresty/openssl111/lib/libssl.so.1.1" {
			t.Errorf("Package = %q", v.Package)
		}
		if v.Installed != "1.1.1w" {
			t.Errorf("Installed = %q", v.Installed)
		}
		if v.Fixed != "1.1.1za" {
			t.Errorf("Fixed = %q", v.Fixed)
		}
	})

	t.Run("sql server style", func(t *testing.T) {
		output := `
  KB : 5040936
  - C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\sqlservr.exe has not been patched.
    Remote version : 2022.160.1000.6
    Should be      : 2022.160.1121.4

  SQL Server Version   : 16.0.1000.6 Express Edition
  SQL Server Instance  : SQLEXPRESS
`
		results := ParseVersions(output)
		if len(results) != 1 {
			t.Fatalf("len = %d, want 1", len(results))
		}
		v := results[0]
		if v.Package != `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\sqlservr.exe` {
			t.Errorf("Package = %q", v.Package)
		}
		if v.Installed != "2022.160.1000.6" {
			t.Errorf("Installed = %q", v.Installed)
		}
		if v.Fixed != "2022.160.1121.4" {
			t.Errorf("Fixed = %q", v.Fixed)
		}
	})

	t.Run("linux single package", func(t *testing.T) {
		output := `
Remote package installed : gnupg2-2.3.3-4.el9
Should be                : gnupg2-2.3.3-5.el9_7
`
		results := ParseVersions(output)
		if len(results) != 1 {
			t.Fatalf("len = %d, want 1", len(results))
		}
		v := results[0]
		if v.Package != "" {
			t.Errorf("Package = %q, want empty", v.Package)
		}
		if v.Installed != "gnupg2-2.3.3-4.el9" {
			t.Errorf("Installed = %q", v.Installed)
		}
		if v.Fixed != "gnupg2-2.3.3-5.el9_7" {
			t.Errorf("Fixed = %q", v.Fixed)
		}
	})

	t.Run("debian package format", func(t *testing.T) {
		output := `
Remote package installed : libexpat1_2.2.6-2+deb10u4_amd64
Should be                : libexpat1_2.2.6-2+deb10u7_amd64

Remote package installed : openssl_3.0.13-0ubuntu3.4_amd64
Should be                : openssl_3.0.13-0ubuntu3.5_amd64
`
		results := ParseVersions(output)
		if len(results) != 2 {
			t.Fatalf("len = %d, want 2", len(results))
		}
		if results[0].Installed != "libexpat1_2.2.6-2+deb10u4_amd64" {
			t.Errorf("[0].Installed = %q", results[0].Installed)
		}
		if results[0].Fixed != "libexpat1_2.2.6-2+deb10u7_amd64" {
			t.Errorf("[0].Fixed = %q", results[0].Fixed)
		}
		if results[1].Installed != "openssl_3.0.13-0ubuntu3.4_amd64" {
			t.Errorf("[1].Installed = %q", results[1].Installed)
		}
		if results[1].Fixed != "openssl_3.0.13-0ubuntu3.5_amd64" {
			t.Errorf("[1].Fixed = %q", results[1].Fixed)
		}
	})

	t.Run("linux multiple packages", func(t *testing.T) {
		output := `
Remote package installed : kernel-5.14.0-570.17.1.el9_6
Should be                : kernel-5.14.0-611.24.1.el9_7

Remote package installed : kernel-core-5.14.0-570.17.1.el9_6
Should be                : kernel-core-5.14.0-611.24.1.el9_7

Remote package installed : kernel-tools-5.14.0-362.24.1.el9_3
Should be                : kernel-tools-5.14.0-611.24.1.el9_7
`
		results := ParseVersions(output)
		if len(results) != 3 {
			t.Fatalf("len = %d, want 3", len(results))
		}
		if results[0].Installed != "kernel-5.14.0-570.17.1.el9_6" {
			t.Errorf("[0].Installed = %q", results[0].Installed)
		}
		if results[0].Fixed != "kernel-5.14.0-611.24.1.el9_7" {
			t.Errorf("[0].Fixed = %q", results[0].Fixed)
		}
		if results[1].Installed != "kernel-core-5.14.0-570.17.1.el9_6" {
			t.Errorf("[1].Installed = %q", results[1].Installed)
		}
		if results[2].Installed != "kernel-tools-5.14.0-362.24.1.el9_3" {
			t.Errorf("[2].Installed = %q", results[2].Installed)
		}
	})

	t.Run("no version info", func(t *testing.T) {
		results := ParseVersions("The remote host is running SSH.")
		if len(results) != 0 {
			t.Fatalf("len = %d, want 0", len(results))
		}
	})

	t.Run("empty", func(t *testing.T) {
		results := ParseVersions("")
		if len(results) != 0 {
			t.Fatalf("len = %d, want 0", len(results))
		}
	})

	t.Run("installed without fixed is ignored", func(t *testing.T) {
		output := `
  Installed version : 10.8.2
  Some other text here
`
		results := ParseVersions(output)
		if len(results) != 0 {
			t.Fatalf("len = %d, want 0", len(results))
		}
	})

	t.Run("fixed before installed is ignored", func(t *testing.T) {
		output := `
  Fixed version     : 2.0.0
  Installed version : 1.0.0
`
		results := ParseVersions(output)
		if len(results) != 0 {
			t.Fatalf("len = %d, want 0", len(results))
		}
	})

	t.Run("stale path does not leak into linux packages", func(t *testing.T) {
		output := `
  Path              : C:\foo\app.exe
  Fixed version     : 2.0.0
Remote package installed : kernel-5.14.0-1
Should be                : kernel-5.14.0-2
`
		results := ParseVersions(output)
		if len(results) != 1 {
			t.Fatalf("len = %d, want 1", len(results))
		}
		if results[0].Package != "" {
			t.Errorf("Package = %q, want empty (path should not leak)", results[0].Package)
		}
		if results[0].Installed != "kernel-5.14.0-1" {
			t.Errorf("Installed = %q", results[0].Installed)
		}
	})
}
