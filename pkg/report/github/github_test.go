package github_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				Metadata: types.Metadata{
					OS: &ftypes.OS{
						Family: "alpine",
						Name:   "3.14",
						Eosl:   true,
					},
				},
				Results: types.Results{
					{
						Target: "yarn.lock",
						Class:  "lang-pkgs",
						Type:   "yarn",
						Packages: []ftypes.Package{
							{
								Name:         "@xtuc/ieee754",
								Version:      "1.2.0",
								Relationship: ftypes.RelationshipDirect,
							},
							{
								Name:         "@xtuc/long",
								Version:      "4.2.2",
								Relationship: ftypes.RelationshipDirect,
							},
							{
								Name:         "@xtuc/binaryen",
								Version:      "1.37.33",
								Relationship: ftypes.RelationshipIndirect,
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
					{
						Target: "alpine:3.14 (alpine 3.14.10)",
						Class:  "os-pkgs",
						Type:   "alpine",
						Packages: []ftypes.Package{
							{
								ID:         "apk-tools@2.12.7-r0",
								Name:       "apk-tools",
								Version:    "2.12.7-r0",
								Arch:       "x86_64",
								SrcName:    "apk-tools",
								SrcVersion: "2.12.7-r0",
							},
						},
					},
				},
			},
			want: map[string]github.Manifest{
				"alpine:3.14 (alpine 3.14.10)": {
					Name: "alpine",
					Resolved: map[string]github.Package{
						"apk-tools": {
							PackageUrl:   "pkg:apk/alpine/apk-tools@2.12.7-r0?arch=x86_64&distro=3.14",
							Relationship: "direct",
							Scope:        "runtime",
						},
					},
				},
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
		{
			name: "pypi from image",
			report: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "fake_repo.azurecr.io/image_name",
				ArtifactType:  "container_image",
				Metadata: types.Metadata{
					RepoDigests: []string{"fake_repo.azurecr.io/image_name@sha256:a7c92cdcb3d010f6edeb37ddcdbacab14981aa31e7f1140e0097dc1b8e834c49"},
					RepoTags:    []string{"fake_repo.azurecr.io/image_name:latest"},
				},
				Results: types.Results{
					{
						Target: "Python",
						Class:  "lang-pkgs",
						Type:   "python-pkg",
						Packages: []ftypes.Package{
							{
								Name:    "jwcrypto",
								Version: "0.7",
								Licenses: []string{
									"LGPLv3+",
								},
								Layer: ftypes.Layer{
									Digest: "sha256:ddc612ba4e74ea5633a93e19e7c32f61f5f230073b21a070302a61ef5eec5c50",
									DiffID: "sha256:12935ef6ce21a266aef8df75d601cebf7e935edd01e9f19fab16ccb78fbb9a5e",
								},
								FilePath: "opt/pyenv/versions/3.11.2/lib/python3.11/site-packages/jwcrypto-0.7.dist-info/METADATA",
							},
							{
								Name:    "matplotlib",
								Version: "3.5.3",
								Licenses: []string{
									"PSF",
								},
								Layer: ftypes.Layer{
									Digest: "sha256:ddc612ba4e74ea5633a93e19e7c32f61f5f230073b21a070302a61ef5eec5c50",
									DiffID: "sha256:12935ef6ce21a266aef8df75d601cebf7e935edd01e9f19fab16ccb78fbb9a5e",
								},
								FilePath: "opt/pyenv/versions/3.11.2/lib/python3.11/site-packages/matplotlib-3.5.3.dist-info/METADATA",
							},
						},
					},
				},
			},
			want: map[string]github.Manifest{
				"Python": {
					Name: "python-pkg",
					File: &github.File{
						SrcLocation: "fake_repo.azurecr.io/image_name:latest@sha256:a7c92cdcb3d010f6edeb37ddcdbacab14981aa31e7f1140e0097dc1b8e834c49",
					},
					Resolved: map[string]github.Package{
						"jwcrypto": {
							PackageUrl:   "pkg:pypi/jwcrypto@0.7",
							Relationship: "direct",
							Scope:        "runtime",
							Metadata:     github.Metadata{"source_location": "opt/pyenv/versions/3.11.2/lib/python3.11/site-packages/jwcrypto-0.7.dist-info/METADATA"},
						},
						"matplotlib": {
							PackageUrl:   "pkg:pypi/matplotlib@3.5.3",
							Relationship: "direct",
							Scope:        "runtime",
							Metadata:     github.Metadata{"source_location": "opt/pyenv/versions/3.11.2/lib/python3.11/site-packages/matplotlib-3.5.3.dist-info/METADATA"},
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

			err := w.Write(context.Background(), inputResults)
			require.NoError(t, err)

			var got github.DependencySnapshot
			err = json.Unmarshal(written.Bytes(), &got)
			require.NoError(t, err, "invalid github written")
			assert.Equal(t, tt.want, got.Manifests, tt.name)
		})
	}
}
