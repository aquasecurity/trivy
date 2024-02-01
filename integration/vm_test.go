//go:build vm_integration

package integration

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestVM(t *testing.T) {
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
			golden: "testdata/amazonlinux2-gp2-x86-vm.json.golden",
		},
		{
			name: "amazon linux 2 in Snapshot, filesystem XFS",
			args: args{
				input:        "testdata/fixtures/vm-images/amazon-2.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/amazonlinux2-gp2-x86-vm.json.golden",
		},
		{
			name: "Ubuntu in Snapshot, filesystem EXT4",
			args: args{
				input:        "testdata/fixtures/vm-images/ubuntu-2204.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/ubuntu-gp2-x86-vm.json.golden",
		},
		{
			name: "Ubuntu in VMDK, filesystem EXT4",
			args: args{
				input:        "testdata/fixtures/vm-images/ubuntu-2204.vmdk.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/ubuntu-gp2-x86-vm.json.golden",
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
			}

			// Decompress the gzipped image file
			imagePath := filepath.Join(t.TempDir(), imageFile)
			testutil.DecompressSparseGzip(t, tt.args.input, imagePath)

			osArgs = append(osArgs, imagePath)

			// Run "trivy vm"
			runTest(t, osArgs, tt.golden, "", types.FormatJSON, runOptions{
				override: func(_, got *types.Report) {
					got.ArtifactName = "disk.img"
					for i := range got.Results {
						lastIndex := strings.LastIndex(got.Results[i].Target, "/")
						got.Results[i].Target = got.Results[i].Target[lastIndex+1:]
					}
				},
			})
		})
	}
}
