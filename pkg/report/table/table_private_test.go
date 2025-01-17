package table

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tml"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
	jarVuln = types.Result{
		Target: "Java",
		Class:  types.ClassLangPkg,
		Type:   ftypes.Jar,
		Vulnerabilities: []types.DetectedVulnerability{
			{
				VulnerabilityID: "CVE-2022-42003",
				PkgName:         "com.fasterxml.jackson.core:jackson-databind",
				PkgPath:         "app/jackson-databind-2.13.4.1.jar",
			},
			{
				VulnerabilityID: "CVE-2021-44832",
				PkgName:         "org.apache.logging.log4j:log4j-core",
				PkgPath:         "app/log4j-core-2.17.0.jar",
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
	fileLicense = types.Result{
		Target: "Loose File License(s)",
		Class:  types.ClassLicenseFile,
	}
)

func Test_renderSummary(t *testing.T) {
	tests := []struct {
		name           string
		scanners       types.Scanners
		noSummaryTable bool
		report         types.Report
		want           string
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
					jarVuln,
					dockerfileMisconfig,
					secret,
					osLicense,
					jarLicense,
					fileLicense,
				},
			},
			want: `
Report Summary

┌───────────────────────┬────────────┬─────────────────┬───────────────────┬─────────┬──────────┐
│        Target         │    Type    │ Vulnerabilities │ Misconfigurations │ Secrets │ Licenses │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ test (alpine 3.20.3)  │   alpine   │        2        │         -         │    -    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ Java                  │    jar     │        2        │         -         │    -    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ app/Dockerfile        │ dockerfile │        -        │         2         │    -    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ requirements.txt      │    text    │        -        │         -         │    1    │    -     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ OS Packages           │     -      │        -        │         -         │    -    │    1     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ Java                  │     -      │        -        │         -         │    -    │    0     │
├───────────────────────┼────────────┼─────────────────┼───────────────────┼─────────┼──────────┤
│ Loose File License(s) │     -      │        -        │         -         │    -    │    -     │
└───────────────────────┴────────────┴─────────────────┴───────────────────┴─────────┴──────────┘
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
					jarVuln,
				},
			},
			want: `
Report Summary

┌──────────────────────┬────────┬─────────────────┐
│        Target        │  Type  │ Vulnerabilities │
├──────────────────────┼────────┼─────────────────┤
│ test (alpine 3.20.3) │ alpine │        2        │
├──────────────────────┼────────┼─────────────────┤
│ Java                 │  jar   │        2        │
└──────────────────────┴────────┴─────────────────┘
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
					jarVuln,
				},
			},
			want: `
Report Summary

┌──────────────────────┬────────┬─────────────────┐
│        Target        │  Type  │ Vulnerabilities │
├──────────────────────┼────────┼─────────────────┤
│ test (alpine 3.20.3) │ alpine │        2        │
├──────────────────────┼────────┼─────────────────┤
│ Java                 │  jar   │        2        │
└──────────────────────┴────────┴─────────────────┘
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tml.DisableFormatting()
			tableWritten := bytes.Buffer{}
			writer := Writer{
				Output:         &tableWritten,
				Scanners:       tt.scanners,
				NoSummaryTable: tt.noSummaryTable,
			}
			err := writer.renderSummary(tt.report)
			require.NoError(t, err)
			assert.Equal(t, tt.want, tableWritten.String())
		})
	}
}
