package table_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	osVuln = types.Result{
		Target: "test (alpine 3.20.3)",
		Class:  types.ClassOSPkg,
		Type:   ftypes.Alpine,
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID: "CVE-2024-9143",
				PkgName:         "libcrypto3",
			},
			{
				VulnerabilityID: "CVE-2024-9143",
				PkgName:         "libssl3",
			},
		},
	}
	jarVulns = types.Result{
		Target: "Java",
		Class:  types.ClassLangPkg,
		Type:   ftypes.Jar,
		Packages: []ftypes.Package{
			{
				Name:     "com.fasterxml.jackson.core:jackson-databind",
				FilePath: "app/jackson-databind-2.13.4.1.jar",
			},
			{
				Name:     "com.google.code.gson:gson",
				FilePath: "app/gson-2.11.0.jar",
			},
			{
				Name:     "org.apache.logging.log4j:log4j-core",
				FilePath: "app/jackson-databind-2.13.4.1.jar/nested/app2/log4j-core-2.17.0.jar",
			},
		},
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID: "CVE-2022-42003",
				PkgName:         "com.fasterxml.jackson.core:jackson-databind",
				PkgPath:         "app/jackson-databind-2.13.4.1.jar",
			},
			{
				VulnerabilityID: "CVE-2021-44832",
				PkgName:         "org.apache.logging.log4j:log4j-core",
				PkgPath:         "app/jackson-databind-2.13.4.1.jar/nested/app2/log4j-core-2.17.0.jar",
			},
		},
	}

	npmVulns = types.Result{
		Target: "Node.js",
		Class:  types.ClassLangPkg,
		Type:   ftypes.NodePkg,
		Packages: []ftypes.Package{
			{
				Name:     "loader-utils@2.0.2",
				FilePath: "loader-utils/package.json",
			},
			{
				Name:     "nanoid@3.1.25",
				FilePath: "nanoid/package.json",
			},
		},
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID: "CVE-2022-37601",
				PkgName:         "loader-utils",
				PkgPath:         "loader-utils/package.json",
			},
			{
				VulnerabilityID: "CVE-2022-37599",
				PkgName:         "loader-utils",
				PkgPath:         "loader-utils/package.json",
			},
			{
				VulnerabilityID: "CVE-2021-23566",
				PkgName:         "nanoid",
				PkgPath:         "nanoid/package.json",
			},
			{
				VulnerabilityID: "CVE-2024-55565",
				PkgName:         "nanoid",
				PkgPath:         "nanoid/package.json",
			},
		},
	}

	noVuln = types.Result{
		Target: "requirements.txt",
		Class:  types.ClassLangPkg,
		Type:   ftypes.Pip,
	}

	dockerfileMisconfig = types.Result{
		Target: "app/Dockerfile",
		Class:  types.ClassConfig,
		Type:   ftypes.Dockerfile,
		Misconfigurations: []types.DetectedMisconfiguration{
			{
				ID: "DS002",
			},
			{
				ID: "DS026",
			},
		},
	}
	secret = types.Result{
		Target: "requirements.txt",
		Class:  types.ClassSecret,
		Secrets: []types.DetectedSecret{
			{
				RuleID: "aws-access-key-id",
			},
		},
	}
	osLicense = types.Result{
		Target: "OS Packages",
		Class:  types.ClassLicense,
		Licenses: []types.DetectedLicense{
			{
				Name: "GPL-2.0-only",
			},
		},
	}

	jarLicense = types.Result{
		Target: "Java",
		Class:  types.ClassLicense,
	}

	npmLicenses = types.Result{
		Target: "Node.js",
		Class:  types.ClassLicense,
		Licenses: []types.DetectedLicense{
			{
				Name:     "MIT",
				FilePath: "loader-utils/package.json",
				Category: "notice",
			},
			{
				Name:     "MIT",
				FilePath: "nanoid/package.json",
				Category: "notice",
			},
		},
	}

	fileLicense = types.Result{
		Target: "Loose File License(s)",
		Class:  types.ClassLicenseFile,
		Licenses: []types.DetectedLicense{
			{
				FilePath: "LICENSE",
			},
		},
	}
)

func Test_renderSummary(t *testing.T) {
	tests := []struct {
		name     string
		scanners types.Scanners
		report   types.Report
		want     string
	}{
		{
			name: "happy path all scanners",
			scanners: []types.Scanner{
				types.VulnerabilityScanner,
				types.MisconfigScanner,
				types.SecretScanner,
				types.LicenseScanner,
			},
			report: types.Report{
				Results: []types.Result{
					osVuln,
					jarVulns,
					npmVulns,
					dockerfileMisconfig,
					secret,
					osLicense,
					jarLicense,
					npmLicenses,
					fileLicense,
				},
			},
			want: `
Report Summary

┌───────────────────────────────────┬────────────┬─────────────────┬───────────────────┬─────────┬──────────┐
│              Target               │    Type    │ Vulnerabilities │ Misconfigurations │ Secrets │ Licenses │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ test (alpine 3.20.3)              │   alpine   │        2        │         -         │    -    │    -     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ app/gson-2.11.0.jar               │    jar     │        0        │         -         │    -    │    -     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ app/jackson-databind-2.13.4.1.jar │    jar     │        2        │         -         │    -    │    -     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ loader-utils/package.json         │  node-pkg  │        2        │         -         │    -    │    -     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ nanoid/package.json               │  node-pkg  │        2        │         -         │    -    │    -     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ app/Dockerfile                    │ dockerfile │        -        │         2         │    -    │    -     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ requirements.txt                  │    text    │        -        │         -         │    1    │    -     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ OS Packages                       │     -      │        -        │         -         │    -    │    1     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ loader-utils/package.json         │     -      │        -        │         -         │    -    │    1     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ nanoid/package.json               │     -      │        -        │         -         │    -    │    1     │
├───────────────────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ Loose File License(s)             │     -      │        -        │         -         │    -    │    1     │
└───────────────────────────────────┴────────────┴─────────────────┴───────────────────┴─────────┴──────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

`,
		},
		{
			name: "happy path vuln scanner only",
			scanners: []types.Scanner{
				types.VulnerabilityScanner,
			},
			report: types.Report{
				Results: []types.Result{
					osVuln,
					jarVulns,
				},
			},
			want: `
Report Summary

┌───────────────────────────────────┬────────┬─────────────────┐
│              Target               │  Type  │ Vulnerabilities │
├───────────────────────────────────┼────────┼─────────────────┤
│ test (alpine 3.20.3)              │ alpine │        2        │
├───────────────────────────────────┼────────┼─────────────────┤
│ app/gson-2.11.0.jar               │  jar   │        0        │
├───────────────────────────────────┼────────┼─────────────────┤
│ app/jackson-databind-2.13.4.1.jar │  jar   │        2        │
└───────────────────────────────────┴────────┴─────────────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

`,
		},
		{
			name: "happy path no vulns + secret",
			scanners: []types.Scanner{
				types.VulnerabilityScanner,
				types.SecretScanner,
			},
			report: types.Report{
				Results: []types.Result{
					noVuln,
					secret,
				},
			},
			want: `
Report Summary

┌──────────────────┬──────┬─────────────────┬─────────┐
│      Target      │ Type │ Vulnerabilities │ Secrets │
├──────────────────┼──────┼─────────────────┼─────────┤
│ requirements.txt │ pip  │        0        │    -    │
├──────────────────┼──────┼─────────────────┼─────────┤
│ requirements.txt │ text │        -        │    1    │
└──────────────────┴──────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

`,
		},
		{
			name: "happy path without supported files for vulns + secret",
			scanners: []types.Scanner{
				types.VulnerabilityScanner,
				types.SecretScanner,
			},
			want: `
Report Summary

┌────────┬──────┬─────────────────┬─────────┐
│ Target │ Type │ Vulnerabilities │ Secrets │
├────────┼──────┼─────────────────┼─────────┤
│   -    │  -   │        -        │    -    │
└────────┴──────┴─────────────────┴─────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

`,
		},
		{
			name: "happy path without supported files for all scanners",
			scanners: []types.Scanner{
				types.VulnerabilityScanner,
				types.SecretScanner,
				types.MisconfigScanner,
				types.LicenseScanner,
			},
			want: `
Report Summary

┌────────┬──────┬─────────────────┬─────────┬───────────────────┬──────────┐
│ Target │ Type │ Vulnerabilities │ Secrets │ Misconfigurations │ Licenses │
├────────┼──────┼─────────────────┼─────────┼───────────────────┼──────────┤
│   -    │  -   │        -        │    -    │         -         │    -     │
└────────┴──────┴─────────────────┴─────────┴───────────────────┴──────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			r := table.NewSummaryRenderer(buf, false, tt.scanners)
			r.Render(tt.report)
			require.Equal(t, tt.want, buf.String())
		})
	}
}
