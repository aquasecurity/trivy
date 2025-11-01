//go:build vm_integration

package integration

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/types"
)

// TestVM tests scanning VM images (VMDK, disk images).
//
// TODO: Golden files cannot be updated with the -update flag currently because
// ArtifactName contains random file paths from t.TempDir() and Target contains full paths.
// This test applies overrides to normalize these values for comparison, but those overrides
// would not be applied to golden files in update mode.
// For now, golden files must be updated manually.
func TestVM(t *testing.T) {
	if *update {
		t.Fatal("TestVM does not support -update flag. Golden files must be updated manually. See TODO comment above.")
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
		override types.Report
	}{
		{
			name: "amazon linux 2 in VMDK, filesystem XFS",
			args: args{
				input:        "testdata/fixtures/vm-images/amazon-2.vmdk.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: goldenAmazonLinux2GP2X86VM,
		},
		{
			name: "amazon linux 2 in Snapshot, filesystem XFS",
			args: args{
				input:        "testdata/fixtures/vm-images/amazon-2.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: goldenAmazonLinux2GP2X86VM,
		},
		{
			name: "Ubuntu in Snapshot, filesystem EXT4",
			args: args{
				input:        "testdata/fixtures/vm-images/ubuntu-2204.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: goldenUbuntuGP2X86VM,
		},
		{
			name: "Ubuntu in VMDK, filesystem EXT4",
			args: args{
				input:        "testdata/fixtures/vm-images/ubuntu-2204.vmdk.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: goldenUbuntuGP2X86VM,
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	const imageFile = "disk.img"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"--cache-dir",
				cacheDir,
				"vm",
				"--scanners",
				"vuln",
				"-q",
				"--skip-db-update",
				"--format",
				tt.args.format,
				"--list-all-pkgs=false",
			}

			// Decompress the gzipped image file
			imagePath := filepath.Join(t.TempDir(), imageFile)
			testutil.DecompressSparseGzip(t, tt.args.input, imagePath)

			osArgs = append(osArgs, imagePath)

			// Run "trivy vm"
			runTest(t, osArgs, tt.golden, types.FormatJSON, runOptions{
				override: overrideFuncs(overrideUID, func(t *testing.T, _, got *types.Report) {
					got.ArtifactName = "disk.img"
					for i := range got.Results {
						lastIndex := strings.LastIndex(got.Results[i].Target, "/")
						got.Results[i].Target = got.Results[i].Target[lastIndex+1:]
					}
				}),
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			})
		})
	}
}
