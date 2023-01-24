//go:build integration

package integration

import (
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestSBOM(t *testing.T) {
	type args struct {
		input        string
		format       string
		artifactType string
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
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			golden: "testdata/centos-7-cyclonedx.json.golden",
		},
		{
			name: "fluentd-multiple-lockfiles cyclonedx",
			args: args{
				input:        "testdata/fixtures/sbom/fluentd-multiple-lockfiles-cyclonedx.json",
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			golden: "testdata/fluentd-multiple-lockfiles-cyclonedx.json.golden",
		},
		{
			name: "centos7 in in-toto attestation",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl",
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			golden: "testdata/centos-7-cyclonedx.json.golden",
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
						Vulnerabilities: []types.DetectedVulnerability{
							{Ref: "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810"},
							{Ref: "pkg:rpm/centos/openssl-libs@1:1.0.2k-16.el7?arch=x86_64&distro=centos-7.6.1810"},
							{Ref: "pkg:rpm/centos/openssl-libs@1:1.0.2k-16.el7?arch=x86_64&distro=centos-7.6.1810"},
						},
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
						Vulnerabilities: []types.DetectedVulnerability{
							{Ref: "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810"},
							{Ref: "pkg:rpm/centos/openssl-libs@1:1.0.2k-16.el7?arch=x86_64&distro=centos-7.6.1810"},
							{Ref: "pkg:rpm/centos/openssl-libs@1:1.0.2k-16.el7?arch=x86_64&distro=centos-7.6.1810"},
						},
					},
				},
			},
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"--cache-dir", cacheDir, "sbom", "-q", "--skip-db-update", "--format", tt.args.format,
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
			case "cyclonedx":
				compareCycloneDX(t, tt.golden, outputFile)
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

	want.ArtifactName = overrideWant.ArtifactName
	want.ArtifactType = overrideWant.ArtifactType
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
			want.Results[i].Vulnerabilities[j].Ref = vuln.Ref
		}
	}

	got := readReport(t, gotFile)
	assert.Equal(t, want, got)
}
