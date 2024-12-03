package table_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestWriter_Write(t *testing.T) {
	testCases := []struct {
		name               string
		results            types.Results
		expectedOutput     string
		includeNonFailures bool
	}{
		{
			name: "vulnerability and custom resource",
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
							Status:           dbTypes.StatusWillNotFix,
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
			expectedOutput: `
test ()
=======
Total: 1 (MEDIUM: 0, HIGH: 1)

┌─────────┬───────────────┬──────────┬──────────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
│ Library │ Vulnerability │ Severity │    Status    │ Installed Version │ Fixed Version │                   Title                   │
├─────────┼───────────────┼──────────┼──────────────┼───────────────────┼───────────────┼───────────────────────────────────────────┤
│ foo     │ CVE-2020-0001 │ HIGH     │ will_not_fix │ 1.2.3             │               │ foobar                                    │
│         │               │          │              │                   │               │ https://avd.aquasec.com/nvd/cve-2020-0001 │
└─────────┴───────────────┴──────────┴──────────────┴───────────────────┴───────────────┴───────────────────────────────────────────┘
`,
		},
		{
			name: "no vulns",
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
				},
			},
			expectedOutput: ``,
		},
	}

	t.Setenv("TRIVY_DISABLE_VEX_NOTICE", "1")
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tableWritten := bytes.Buffer{}
			writer := table.Writer{
				Output:             &tableWritten,
				Tree:               true,
				IncludeNonFailures: tc.includeNonFailures,
				Severities: []dbTypes.Severity{
					dbTypes.SeverityHigh,
					dbTypes.SeverityMedium,
				},
			}
			err := writer.Write(nil, types.Report{Results: tc.results})
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}
