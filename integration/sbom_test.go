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
// Golden file update policy:
// - Test cases with `update: false` use golden files shared with TestTar and cannot be updated with -update flag
//   - Shared golden files should be updated via TestTar
//
// - Test cases with `update: true` use SBOM-specific golden files that can be updated with -update flag
//   - SBOM-specific golden files can be updated by running this test with -update flag
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
		fakeUUID string
		override OverrideFunc
		update   bool // whether this test case can update its golden file with -update flag
	}{
		{
			name: "centos7 cyclonedx",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden:   goldenCentOS7,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			update:   false, // Shared with TestTar
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-cyclonedx.json"
				want.ArtifactType = ftypes.TypeCycloneDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-cyclonedx.json (centos 7.6.1810)"

				require.Len(t, got.Results[0].Vulnerabilities, 3)
				want.Results[0].Vulnerabilities[0].PkgIdentifier.BOMRef = "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[1].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[2].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"

				// SBOM parsing consumes UUIDs #1-#4 for components, so ReportID becomes #5
				want.ReportID = "3ff14136-e09f-4df9-80ea-000000000005"
			},
		},
		{
			name: "centos7 spdx tag-value",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.txt",
				format:       "json",
				artifactType: "spdx",
			},
			golden:   goldenCentOS7,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			update:   false, // Shared with TestTar
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-spdx.txt"
				want.ArtifactType = ftypes.TypeSPDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-spdx.txt (centos 7.6.1810)"

				// SBOM parsing consumes UUIDs #1-#4 for components, so ReportID becomes #5
				want.ReportID = "3ff14136-e09f-4df9-80ea-000000000005"
			},
		},
		{
			name: "centos7 spdx json",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.json",
				format:       "json",
				artifactType: "spdx",
			},
			golden:   goldenCentOS7,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			update:   false, // Shared with TestTar
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-spdx.json"
				want.ArtifactType = ftypes.TypeSPDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-spdx.json (centos 7.6.1810)"

				// SBOM parsing consumes UUIDs #1-#4 for components, so ReportID becomes #5
				want.ReportID = "3ff14136-e09f-4df9-80ea-000000000005"
			},
		},
		{
			name: "fluentd-multiple-lockfiles cyclonedx",
			args: args{
				input:        "testdata/fixtures/sbom/fluentd-multiple-lockfiles-cyclonedx.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden:   goldenFluentdMultipleLockfiles,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			update:   true, // SBOM-specific golden file
		},
		{
			name: "scan SBOM into SBOM",
			args: args{
				input:        "testdata/fixtures/sbom/fluentd-multiple-lockfiles-cyclonedx.json",
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			golden:   goldenFluentdMultipleLockfilesShortCDX,
			update:   true, // SBOM-specific golden file
		},
		{
			name: "minikube KBOM",
			args: args{
				input:        "testdata/fixtures/sbom/minikube-kbom.json",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden:   goldenMinikubeKBOM,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			update:   true, // SBOM-specific golden file
		},
		{
			name: "centos7 in in-toto attestation",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl",
				format:       "json",
				artifactType: "cyclonedx",
			},
			golden:   goldenCentOS7,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			update:   false, // Shared with TestTar
			override: func(t *testing.T, want, got *types.Report) {
				want.ArtifactName = "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl"
				want.ArtifactType = ftypes.TypeCycloneDX

				require.Len(t, got.Results, 1)
				want.Results[0].Target = "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl (centos 7.6.1810)"

				require.Len(t, got.Results[0].Vulnerabilities, 3)
				want.Results[0].Vulnerabilities[0].PkgIdentifier.BOMRef = "pkg:rpm/centos/bash@4.2.46-31.el7?arch=x86_64&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[1].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"
				want.Results[0].Vulnerabilities[2].PkgIdentifier.BOMRef = "pkg:rpm/centos/openssl-libs@1.0.2k-16.el7?arch=x86_64&epoch=1&distro=centos-7.6.1810"

				// SBOM parsing consumes UUIDs #1-#4 for components, so ReportID becomes #5
				want.ReportID = "3ff14136-e09f-4df9-80ea-000000000005"
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
			golden:   goldenLicenseCycloneDX,
			fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			update:   true, // SBOM-specific golden file
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
			runTest(t, osArgs, tt.golden, "", types.Format(tt.args.format), runOptions{
				override: overrideFuncs(overrideSBOMReport, overrideUID, tt.override),
				fakeUUID: tt.fakeUUID,
				update:   tt.update && *update, // Controlled by test case update field and -update flag
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
