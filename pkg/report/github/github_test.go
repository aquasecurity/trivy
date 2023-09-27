package github_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report/github"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestWriter_Write(t *testing.T) {
	tests := []struct {
		name   string
		report types.Report
		want   map[string]github.Manifest
	}{
		{
			name: "os packages",
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
			want: map[string]github.Manifest{
				"yarn.lock": {
					Name: "yarn",
					File: &github.File{
						SrcLocation: "yarn.lock",
					},
					Resolved: map[string]github.Package{
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
			name: "maven",
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
			want: map[string]github.Manifest{
				"pom.xml": {
					Name: "pom",
					File: &github.File{
						SrcLocation: "pom.xml",
					},
					Resolved: map[string]github.Package{
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			written := bytes.NewBuffer(nil)
			w := github.Writer{
				Output: written,
			}

			inputResults := tt.report

			err := w.Write(inputResults)
			assert.NoError(t, err)

			var got github.DependencySnapshot
			err = json.Unmarshal(written.Bytes(), &got)
			assert.NoError(t, err, "invalid github written")
			assert.Equal(t, tt.want, got.Manifests, tt.name)
		})
	}
}
