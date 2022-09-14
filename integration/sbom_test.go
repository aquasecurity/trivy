//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSBOM(t *testing.T) {
	type args struct {
		input        string
		format       string
		artifactType string
	}
	tests := []struct {
		name   string
		args   args
		golden string
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
			golden: "testdata/centos-7-spdx.json.golden",
		},
		{
			name: "centos7 spdx json",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.json",
				format:       "json",
				artifactType: "spdx-json",
			},
			golden: "testdata/centos-7-spdx.json.golden",
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
				want := decodeCycloneDX(t, tt.golden)
				got := decodeCycloneDX(t, outputFile)
				assert.Equal(t, want, got)
			case "json":
				compareReports(t, tt.golden, outputFile)
			default:
				require.Fail(t, "invalid format", "format: %s", tt.args.format)
			}
		})
	}
}

func decodeCycloneDX(t *testing.T, filePath string) *cdx.BOM {
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	require.NoError(t, err)

	bom.Metadata.Timestamp = ""

	return bom
}
