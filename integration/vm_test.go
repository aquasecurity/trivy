//go:build vm_integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

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

	// Keep the current working directory
	currentDir, err := os.Getwd()
	require.NoError(t, err)

	const imageFile = "disk.img"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"--cache-dir", cacheDir, "vm", "--security-checks", "vuln", "-q", "--skip-db-update",
				"--format", tt.args.format,
			}

			tmpDir := t.TempDir()

			// Set up the output file
			outputFile := filepath.Join(tmpDir, "output.json")
			if *update {
				outputFile = tt.golden
			}

			// Get the absolute path of the golden file
			goldenFile, err := filepath.Abs(tt.golden)
			require.NoError(t, err)

			// Decompress the gzipped image file
			imagePath := filepath.Join(tmpDir, imageFile)
			testutil.DecompressGzip(t, tt.args.input, imagePath)

			// Change the current working directory so that targets in the result could be the same as golden files.
			err = os.Chdir(tmpDir)
			require.NoError(t, err)
			defer os.Chdir(currentDir)

			osArgs = append(osArgs, "--output", outputFile)
			osArgs = append(osArgs, imageFile)

			// Run "trivy vm"
			err = execute(osArgs)
			require.NoError(t, err)
			compareReports(t, goldenFile, outputFile)
		})
	}
}
