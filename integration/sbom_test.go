//go:build integration

package integration

import (
	"path/filepath"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestSBOM(t *testing.T) {
	type args struct {
		input        string
		format       string
		artifactType string
		scanners     string
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		override types.Report
	}{
		{
			name: "centos7 cyclonedx",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: "testdata/centos-7.json.golden",
			override: types.Report{
				ArtifactName: "testdata/fixtures/sbom/centos-7-cyclonedx.json",
				ArtifactType: ftypes.ArtifactType("cyclonedx"),
				Results: types.Results{
					{
						Target: "testdata/fixtures/sbom/centos-7-cyclonedx.json (centos 7.6.1810)",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgIdentifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810",
								},
							},
							{
								PkgIdentifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810",
								},
							},
							{
								PkgIdentifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "fluentd-multiple-lockfiles cyclonedx",
			args: args{
				input:        "testdata/fixtures/sbom/fluentd-multiple-lockfiles-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: "testdata/fluentd-multiple-lockfiles.json.golden",
		},
		{
			name: "minikube KBOM",
			args: args{
				input:        "testdata/fixtures/sbom/minikube-kbom.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: "testdata/minikube-kbom.json.golden",
		},
		{
			name: "centos7 in in-toto attestation",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: "testdata/centos-7.json.golden",
			override: types.Report{
				ArtifactName: "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl",
				ArtifactType: ftypes.ArtifactType("cyclonedx"),
				Results: types.Results{
					{
						Target: "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl (centos 7.6.1810)",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgIdentifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810",
								},
							},
							{
								PkgIdentifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810",
								},
							},
							{
								PkgIdentifier: ftypes.PkgIdentifier{
									BOMRef: "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "centos7 spdx tag-value",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.txt",
				format:       "json",
				artifactType: "spdx",
			},
			golden: "testdata/centos-7.json.golden",
			override: types.Report{
				ArtifactName: "testdata/fixtures/sbom/centos-7-spdx.txt",
				ArtifactType: ftypes.ArtifactType("spdx"),
				Results: types.Results{
					{
						Target: "testdata/fixtures/sbom/centos-7-spdx.txt (centos 7.6.1810)",
					},
				},
			},
		},
		{
			name: "centos7 spdx json",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.json",
				format:       "json",
				artifactType: "spdx",
			},
			golden: "testdata/centos-7.json.golden",
			override: types.Report{
				ArtifactName: "testdata/fixtures/sbom/centos-7-spdx.json",
				ArtifactType: ftypes.ArtifactType("spdx"),
				Results: types.Results{
					{
						Target: "testdata/fixtures/sbom/centos-7-spdx.json (centos 7.6.1810)",
					},
				},
			},
		},
		{
			name: "license check cyclonedx json",
			args: args{
				input:        "testdata/fixtures/sbom/license-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
				scanners:     "license",
			},
			golden: "testdata/license-cyclonedx.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanners := "vuln"
			if tt.args.scanners != "" {
				scanners = tt.args.scanners
			}

			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"sbom",
				"-q",
				"--skip-db-update",
				"--format",
				tt.args.format,
				"--scanners",
				scanners,
			}

			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			osArgs = append(osArgs, "--output", outputFile)
			osArgs = append(osArgs, tt.args.input)

			// Run "trivy sbom"
			err := execute(osArgs)
			assert.NoError(t, err)

			// Compare want and got
			switch tt.args.format {
			case "json":
				compareSBOMReports(t, tt.golden, outputFile, tt.override)
			default:
				require.Fail(t, "invalid format", "format: %s", tt.args.format)
			}
		})
	}
}

// TODO(teppei): merge into compareReports
func compareSBOMReports(t *testing.T, wantFile, gotFile string, overrideWant types.Report) {
	want := readReport(t, wantFile)

	if overrideWant.ArtifactName != "" {
		want.ArtifactName = overrideWant.ArtifactName
	}
	if overrideWant.ArtifactType != "" {
		want.ArtifactType = overrideWant.ArtifactType
	}
	want.Metadata.ImageID = ""
	want.Metadata.ImageConfig = v1.ConfigFile{}
	want.Metadata.DiffIDs = nil
	for i, result := range want.Results {
		for j := range result.Vulnerabilities {
			want.Results[i].Vulnerabilities[j].Layer.DiffID = ""
		}
	}

	for i, result := range overrideWant.Results {
		want.Results[i].Target = result.Target
		for j, vuln := range result.Vulnerabilities {
			if vuln.PkgIdentifier.PURL != nil {
				want.Results[i].Vulnerabilities[j].PkgIdentifier.PURL = vuln.PkgIdentifier.PURL
			}
			if vuln.PkgIdentifier.BOMRef != "" {
				want.Results[i].Vulnerabilities[j].PkgIdentifier.BOMRef = vuln.PkgIdentifier.BOMRef
			}
		}
	}

	got := readReport(t, gotFile)
	// when running on Windows FS
	got.ArtifactName = filepath.ToSlash(filepath.Clean(got.ArtifactName))
	for i, result := range got.Results {
		got.Results[i].Target = filepath.ToSlash(filepath.Clean(result.Target))
	}
	assert.Equal(t, want, got)
}
