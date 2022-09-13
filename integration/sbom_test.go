//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/jsonloader"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tvloader"
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
			name: "centos7-bom by trivy",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.json",
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			golden: "testdata/centos-7-cyclonedx.json.golden",
		},
		{
			name: "fluentd-multiple-lockfiles-bom by trivy",
			args: args{
				input:        "testdata/fixtures/sbom/fluentd-multiple-lockfiles-cyclonedx.json",
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			golden: "testdata/fluentd-multiple-lockfiles-cyclonedx.json.golden",
		},
		{
			name: "centos7-bom in in-toto attestation",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-cyclonedx.intoto.jsonl",
				format:       "cyclonedx",
				artifactType: "cyclonedx",
			},
			golden: "testdata/centos-7-cyclonedx.json.golden",
		},
		{
			name: "centos7 spdx type tag-value by trivy",
			args: args{
				input:        "testdata/fixtures/sbom/centos-7-spdx.txt",
				format:       "json",
				artifactType: "spdx",
			},
			golden: "testdata/centos-7-spdx-tv.json.golden",
		},
		{
			name: "centos7 spdx type json by trivy",
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

			// Setup the output file
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
			switch tt.args.artifactType {
			case "cyclonedx":
				want := decodeCycloneDX(t, tt.golden)
				got := decodeCycloneDX(t, outputFile)
				assert.Equal(t, want, got)
			case "spdx", "spdx-json":
				want := decodeSPDX(t, tt.args.format, tt.golden)
				got := decodeSPDX(t, tt.args.format, outputFile)
				assert.Equal(t, want, got)
			default:
				t.Fatalf("invalid arguments format: %q", tt.args.format)
			}
		})
	}
}

func decodeSPDX(t *testing.T, format string, filePath string) *spdx.Document2_2 {
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	var spdxDocument *spdx.Document2_2
	switch format {
	case "spdx-json":
		fmt.Println(filePath)
		spdxDocument, err = jsonloader.Load2_2(f)
		require.NoError(t, err)
	case "spdx":
		fmt.Println(filePath)
		spdxDocument, err = tvloader.Load2_2(f)
		require.NoError(t, err)
	}
	return spdxDocument
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
