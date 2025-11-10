//go:build integration

package integration

import (
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// TestSBOM tests scanning SBOM files (CycloneDX, SPDX).
//
// NOTE: This test CAN update golden files with the -update flag because the golden files
// used here are not shared with other tests. These SBOM-specific golden files are unique
// to this test and should be updated here.
func TestSBOM(t *testing.T) {
	type args struct {
		input        string
		format       string
		artifactType string
		scanners     string
	}
	tests := []struct {
		name   string
		args   args
		golden string
	}{
		{
			name: "fluentd-multiple-lockfiles cyclonedx",
			args: args{
				input:        "testdata/fixtures/sbom/fluentd-multiple-lockfiles-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: goldenFluentdMultipleLockfiles,
		},
		{
			name: "scan SBOM into SBOM",
			args: args{
				input:        "testdata/fixtures/sbom/fluentd-multiple-lockfiles-cyclonedx.json",
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			golden: goldenFluentdMultipleLockfilesShortCDX,
		},
		{
			name: "minikube KBOM",
			args: args{
				input:        "testdata/fixtures/sbom/minikube-kbom.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: goldenMinikubeKBOM,
		},
		{
			name: "license check cyclonedx json",
			args: args{
				input:        "testdata/fixtures/sbom/license-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
				scanners:     "license",
			},
			golden: goldenLicenseCycloneDX,
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
				"sbom",
				"--cache-dir",
				cacheDir,
				"-q",
				"--skip-db-update",
				"--format",
				tt.args.format,
				"--scanners",
				scanners,
				"--list-all-pkgs=false",
				tt.args.input,
			}

			// Run "trivy sbom"
			runTest(t, osArgs, tt.golden, types.Format(tt.args.format), runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: nil, // Do not use overrides - golden files are generated from this test as the canonical source
			})
		})
	}
}

// TestSBOMEquivalence tests that scanning an SBOM produces equivalent results to scanning the original artifact.
//
// This test verifies that scanning an image through SBOM:
//
//	trivy image centos:7 -f cyclonedx -o centos7.cdx.json && trivy sbom centos7.cdx.json
//
// produces the same vulnerability results as direct image scanning:
//
//	trivy image centos:7
//
// IMPORTANT: Golden files used in this test cannot be updated with the -update flag
// because the golden files are shared with TestTar.
// If golden files need to be updated, they should be generated from TestTar.
//
// All golden files used in TestSBOMEquivalence MUST also be used in TestTar
// to ensure they can be properly updated when needed.
func TestSBOMEquivalence(t *testing.T) {
	if *update {
		t.Skipf("Skipping TestSBOMEquivalence when -update flag is set. Golden files should be updated via TestTar.")
	}

	type args struct {
		input        string
		format       string
		artifactType string
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		override OverrideFunc
	}{
		{
			name: "centos7 cyclonedx",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: goldenCentOS7,
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-cyclonedx.json"
				want.ArtifactType = ftypes.TypeCycloneDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-cyclonedx.json (centos 7.6.1810)"

				require.Len(t, got.Results[0].Vulnerabilities, 3)
				want.Results[0].Vulnerabilities[0].PkgIdentifier.BOMRef = "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[1].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[2].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"

				// ReportID uses v7 UUID with independent counter from v4 UUIDs used for SBOM components
				want.ReportID = "017b7d41-e09f-7000-80ea-000000000001"
			},
		},
		{
			name: "centos7 spdx tag-value",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.txt",
				format:       "json",
				artifactType: "spdx",
			},
			golden: goldenCentOS7,
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-spdx.txt"
				want.ArtifactType = ftypes.TypeSPDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-spdx.txt (centos 7.6.1810)"

				// ReportID uses v7 UUID with independent counter from v4 UUIDs used for SBOM components
				want.ReportID = "017b7d41-e09f-7000-80ea-000000000001"
			},
		},
		{
			name: "centos7 spdx json",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.json",
				format:       "json",
				artifactType: "spdx",
			},
			golden: goldenCentOS7,
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-spdx.json"
				want.ArtifactType = ftypes.TypeSPDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-spdx.json (centos 7.6.1810)"

				// ReportID uses v7 UUID with independent counter from v4 UUIDs used for SBOM components
				want.ReportID = "017b7d41-e09f-7000-80ea-000000000001"
			},
		},
		{
			name: "centos7 in in-toto attestation",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden: goldenCentOS7,
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl"
				want.ArtifactType = ftypes.TypeCycloneDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl (centos 7.6.1810)"

				require.Len(t, got.Results[0].Vulnerabilities, 3)
				want.Results[0].Vulnerabilities[0].PkgIdentifier.BOMRef = "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[1].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[2].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"

				// ReportID uses v7 UUID with independent counter from v4 UUIDs used for SBOM components
				want.ReportID = "017b7d41-e09f-7000-80ea-000000000001"
			},
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"sbom",
				"--cache-dir",
				cacheDir,
				"-q",
				"--skip-db-update",
				"--format",
				tt.args.format,
				"--scanners",
				"vuln",
				"--list-all-pkgs=false",
				tt.args.input,
			}

			// Run "trivy sbom"
			runTest(t, osArgs, tt.golden, types.Format(tt.args.format), runOptions{
				override: overrideFuncs(overrideSBOMReport, overrideUID, tt.override),
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			})
		})
	}
}

func overrideSBOMReport(_ *testing.T, want, got *types.Report) {
	want.ArtifactID = ""
	want.Metadata.ImageConfig = v1.ConfigFile{}

	// SBOM file doesn't contain info about layers
	want.Metadata.Size = 0
	want.Metadata.Layers = nil

	// when running on Windows FS
	got.ArtifactName = filepath.ToSlash(filepath.Clean(got.ArtifactName))
	for i, result := range got.Results {
		got.Results[i].Target = filepath.ToSlash(filepath.Clean(result.Target))
	}
}
