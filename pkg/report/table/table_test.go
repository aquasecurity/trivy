package table_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestWriter_Write(t *testing.T) {
	testCases := []struct {
		name               string
		scanners           types.Scanners
		tableModes         []types.TableMode
		results            types.Results
		wantOutput         string
		includeNonFailures bool
	}{
		{
			name: "vulnerability and custom resource",
			scanners: types.Scanners{
				types.VulnerabilityScanner,
			},
			tableModes: types.SupportedTableModes,
			results: types.Results{
				{
					Target: "test",
					Type:   ftypes.Jar,
					Class:  types.ClassLangPkg,
					Packages: []ftypes.Package{
						{
							Name:     "foo",
							Version:  "1.2.3",
							FilePath: "test.jar",
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
							Status:           dbTypes.StatusWillNotFix,
							PkgPath:          "test.jar",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "HIGH",
							},
						},
					},
					CustomResources: []ftypes.CustomResource{
						{
							Type: "test",
							Data: "test",
						},
					},
				},
			},
			wantOutput: `
Report Summary

┌──────────┬──────┬─────────────────┐
│  Target  │ Type │ Vulnerabilities │
├──────────┼──────┼─────────────────┤
│ test.jar │ jar  │        1        │
└──────────┴──────┴─────────────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)


test (jar)
==========
Total: 1 (MEDIUM: 0, HIGH: 1)

┌────────────────┬───────────────┬──────────┬──────────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
│    Library     │ Vulnerability │ Severity │    Status    │ Installed Version │ Fixed Version │                   Title                   │
├────────────────┼───────────────┼──────────┼──────────────┼───────────────────┼───────────────┼───────────────────────────────────────────┤
│ foo (test.jar) │ CVE-2020-0001 │ HIGH     │ will_not_fix │ 1.2.3             │               │ foobar                                    │
│                │               │          │              │                   │               │ https://avd.aquasec.com/nvd/cve-2020-0001 │
└────────────────┴───────────────┴──────────┴──────────────┴───────────────────┴───────────────┴───────────────────────────────────────────┘
`,
		},
		{
			name: "no vulns",
			scanners: types.Scanners{
				types.VulnerabilityScanner,
			},
			tableModes: types.SupportedTableModes,
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Jar,
					Packages: []ftypes.Package{
						{
							Name:     "foo",
							Version:  "1.2.3",
							FilePath: "test.jar",
						},
					},
				},
			},
			wantOutput: `
Report Summary

┌──────────┬──────┬─────────────────┐
│  Target  │ Type │ Vulnerabilities │
├──────────┼──────┼─────────────────┤
│ test.jar │ jar  │        0        │
└──────────┴──────┴─────────────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

`,
		},
		{
			name: "no summary",
			scanners: types.Scanners{
				types.VulnerabilityScanner,
			},
			tableModes: []types.TableMode{
				types.Detailed,
			},
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Jar,
					Packages: []ftypes.Package{
						{
							Name:     "foo",
							Version:  "1.2.3",
							FilePath: "test.jar",
						},
					},
				},
			},
			wantOutput: ``,
		},
		{
			name: "no detailed",
			scanners: types.Scanners{
				types.VulnerabilityScanner,
			},
			tableModes: []types.TableMode{
				types.Summary,
			},
			results: types.Results{
				{
					Target: "test",
					Type:   ftypes.Jar,
					Class:  types.ClassLangPkg,
					Packages: []ftypes.Package{
						{
							Name:     "foo",
							Version:  "1.2.3",
							FilePath: "test.jar",
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
							Status:           dbTypes.StatusWillNotFix,
							PkgPath:          "test.jar",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "HIGH",
							},
						},
					},
				},
			},
			wantOutput: `
Report Summary

┌──────────┬──────┬─────────────────┐
│  Target  │ Type │ Vulnerabilities │
├──────────┼──────┼─────────────────┤
│ test.jar │ jar  │        1        │
└──────────┴──────┴─────────────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)

`,
		},
		{
			name: "no tables",
			scanners: types.Scanners{
				types.VulnerabilityScanner,
			},
			tableModes: []types.TableMode{},
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Jar,
					Packages: []ftypes.Package{
						{
							Name:     "foo",
							Version:  "1.2.3",
							FilePath: "test.jar",
						},
					},
				},
			},
			wantOutput: ``,
		},
		{
			name: "no scanners",
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Jar,
				},
			},
			wantOutput: ``,
		},
	}

	t.Setenv("TRIVY_DISABLE_VEX_NOTICE", "1")
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tableWritten := bytes.Buffer{}
			writer := table.NewWriter(table.Options{
				Output:             &tableWritten,
				Tree:               true,
				IncludeNonFailures: tc.includeNonFailures,
				Severities: []dbTypes.Severity{
					dbTypes.SeverityHigh,
					dbTypes.SeverityMedium,
				},
				Scanners:   tc.scanners,
				TableModes: tc.tableModes,
			})
			_ = writer.Write(nil, types.Report{Results: tc.results})
			assert.Equal(t, tc.wantOutput, tableWritten.String(), tc.name)
		})
	}
}
