//go:build vm_integration

package integration

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

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
				input:        "testdata/fixtures/vm/amazonlinux2-gp2-x86.vmdk.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/amazonlinux2-gp2-x86-vmdk.json.golden",
		},
		{
			name: "amazon linux 2 in Snapshot, filesystem XFS",
			args: args{
				input:        "testdata/fixtures/vm/amazonlinux2-gp2-x86.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/amazonlinux2-gp2-x86-snapshot.json.golden",
		},
		{
			name: "RedHat in Snapshot, filesystem EXT4",
			args: args{
				input:        "testdata/fixtures/vm/redhat-gp2-x86.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/redhat-gp2-x86-snapshot.json.golden",
		},
		{
			name: "Ubuntu in VMDK, filesystem XFS",
			args: args{
				input:        "testdata/fixtures/vm/ubuntu-gp2-x86.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/ubuntu-gp2-x86-snapshot.json.golden",
		},
		{
			name: "SUSE in Snapshot, filesystem EXT4",
			args: args{
				input:        "testdata/fixtures/vm/suse-gp2-x86.img.gz",
				format:       "json",
				artifactType: "vm",
			},
			golden: "testdata/suse-gp2-x86-snapshot.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)
	log.Print(cacheDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"--cache-dir", cacheDir, "vm", "--security-checks", "vuln", "-q", "--skip-db-update", "--format", tt.args.format,
			}

			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			f, err := os.Open(tt.args.input)
			assert.NoError(t, err)
			defer f.Close()
			tr := tar.NewReader(f)

			for {
				hdr, err := tr.Next()
				assert.NoError(t, err)
				if strings.HasSuffix(hdr.Name, ".tar.gz") {
					break
				}
			}

			gr, err := gzip.NewReader(tr)
			assert.NoError(t, err)
			tmpdir := os.TempDir()

			testImagePath := filepath.Join(tmpdir, "target.img")
			tf, err := os.Create(testImagePath)
			assert.NoError(t, err)
			defer os.Remove(testImagePath)

			_, err = io.Copy(tf, gr)
			assert.NoError(t, err)

			osArgs = append(osArgs, "--output", outputFile)
			osArgs = append(osArgs, testImagePath)

			// Run "trivy vm"
			err = execute(osArgs)
			assert.NoError(t, err)
			compareReports(t, tt.golden, outputFile)
		})
	}
}
