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

func TestReportWriter_GithubSBOM(t *testing.T) {
	testCases := []struct {
		name   string
		report types.Report
		want   map[string]report.GithubSbomManifest
	}{
		{
			name: "happy path - packages",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14",
				Results: types.Results{
					{
						Target: "yarn.lock",
						Class:  "lang-pkgs",
						Type:   "yarn",
						Packages: []ftypes.Package{
							{
								Name:    "@xtuc/ieee754",
								Version: "1.2.0",
							},
							{
								Name:    "@xtuc/long",
								Version: "4.2.2",
							},
							{
								Name:     "@xtuc/binaryen",
								Version:  "1.37.33",
								Indirect: true,
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
			want: map[string]report.GithubSbomManifest{
				"yarn.lock": {
					Name: "yarn",
					File: &report.GithubSbomFile{
						SrcLocation: "yarn.lock",
					},
					Resolved: map[string]report.GithubSbomPackage{
						"@xtuc/ieee754": {
							PackageUrl:   "pkg:npm/%40xtuc/ieee754@1.2.0",
							Relationship: "direct",
							Scope:        "runtime",
						},
						"@xtuc/long": {
							PackageUrl:   "pkg:npm/%40xtuc/long@4.2.2",
							Relationship: "direct",
							Scope:        "runtime",
						},
						"@xtuc/binaryen": {
							PackageUrl:   "pkg:npm/%40xtuc/binaryen@1.37.33",
							Relationship: "indirect",
							Scope:        "runtime",
						},
					},
				},
			},
		},
		{
			name: "happy path - maven",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "my-java-app",
				Results: types.Results{
					{
						Target: "pom.xml",
						Class:  "lang-pkgs",
						Type:   "pom",
						Packages: []ftypes.Package{
							{
								Name:    "com.google.code.gson:gson",
								Version: "2.2.2",
							},
							{
								Name:    "net.sf.opencsv:opencsv",
								Version: "2.3",
							},
						},
					},
				},
			},
			want: map[string]report.GithubSbomManifest{
				"pom.xml": {
					Name: "pom",
					File: &report.GithubSbomFile{
						SrcLocation: "pom.xml",
					},
					Resolved: map[string]report.GithubSbomPackage{
						"com.google.code.gson:gson": {
							PackageUrl:   "pkg:maven/com.google.code.gson/gson@2.2.2",
							Relationship: "direct",
							Scope:        "runtime",
						},
						"net.sf.opencsv:opencsv": {
							PackageUrl:   "pkg:maven/net.sf.opencsv/opencsv@2.3",
							Relationship: "direct",
							Scope:        "runtime",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jw := report.GithubSbomWriter{}
			githubSbomWritten := bytes.Buffer{}
			jw.Output = &githubSbomWritten

			inputResults := tc.report

			err := report.Write(inputResults, report.Option{
				Format: "github-sbom",
				Output: &githubSbomWritten,
			})
			assert.NoError(t, err)

			var got report.GithubSbom
			err = json.Unmarshal(githubSbomWritten.Bytes(), &got)
			assert.NoError(t, err, "invalid github-sbom written")

			assert.Equal(t, tc.want, got.Manifests, tc.name)
		})
	}
}
