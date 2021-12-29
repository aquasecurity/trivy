package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportWriter_gSBOM(t *testing.T) {
	testCases := []struct {
		name   string
		report report.Report
		want   map[string]report.GsbomManifest
	}{
		{
			name: "happy path - vuls",
			report: report.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14",
				Results: report.Results{
					{
						Target: "foojson",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-0001",
								PkgName:          "foo",
								InstalledVersion: "1.2.3",
								FixedVersion:     "3.4.5",
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
								Vulnerability: dbTypes.Vulnerability{
									Title:       "foobar",
									Description: "baz",
									Severity:    "HIGH",
								},
							},
						},
					},
				},
			},
			want: map[string]report.GsbomManifest{
				"foojson": {
					Resolved: map[string]report.GsbomPackage{
						"foo": {
							Purl: "pkg:/foo@1.2.3",
						},
					},
				},
			},
		},
		{
			name: "happy path - packages",
			report: report.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14",
				Results: report.Results{
					{
						Target: "foojson",
						Packages: []ftypes.Package{
							{
								Name:    "@xtuc/ieee754",
								Version: "1.2.0",
							},
							{
								Name:    "@xtuc/long",
								Version: "4.2.2",
							},
						},

						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-0001",
								PkgName:          "foo",
								InstalledVersion: "1.2.3",
								FixedVersion:     "3.4.5",
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
								Vulnerability: dbTypes.Vulnerability{
									Title:       "foobar",
									Description: "baz",
									Severity:    "HIGH",
								},
							},
						},
					},
				},
			},
			want: map[string]report.GsbomManifest{
				"foojson": {
					Resolved: map[string]report.GsbomPackage{
						"@xtuc/ieee754": {
							Purl: "pkg:/@xtuc%2Fieee754@1.2.0",
						},
						"@xtuc/long": {
							Purl: "pkg:/@xtuc%2Flong@4.2.2",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jw := report.GsbomWriter{}
			gsbomWritten := bytes.Buffer{}
			jw.Output = &gsbomWritten

			inputResults := tc.report

			err := report.Write(inputResults, report.Option{
				Format: "gsbom",
				Output: &gsbomWritten,
			})
			assert.NoError(t, err)

			var got report.Gsbom
			err = json.Unmarshal(gsbomWritten.Bytes(), &got)
			assert.NoError(t, err, "invalid gsbom written")

			assert.Equal(t, tc.want, got.Manifests, tc.name)
		})
	}
}
