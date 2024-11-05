//go:build integration

package integration

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestConvert(t *testing.T) {
	type args struct {
		input          string
		format         string
		scanners       string
		showSuppressed bool
		listAllPkgs    bool
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		override OverrideFunc
	}{
		{
			name: "npm",
			args: args{
				input:  "testdata/npm.json.golden",
				format: "cyclonedx",
			},
			golden: "testdata/npm-cyclonedx.json.golden",
		},
		{
			name: "npm without package UID",
			args: args{
				input:  "testdata/fixtures/convert/npm.json.golden",
				format: "cyclonedx",
			},
			golden: "testdata/npm-cyclonedx.json.golden",
		},
		{
			name: "npm with suppressed vulnerability",
			args: args{
				input:          "testdata/fixtures/convert/npm-with-suppressed.json.golden",
				format:         "json",
				showSuppressed: true,
				listAllPkgs:    true,
			},
			golden: "testdata/fixtures/convert/npm-with-suppressed.json.golden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"convert",
				"--cache-dir",
				t.TempDir(),
				"-q",
				"--format",
				tt.args.format,
			}

			if tt.args.showSuppressed {
				osArgs = append(osArgs, "--show-suppressed")
			}

			if tt.args.listAllPkgs {
				osArgs = append(osArgs, "--list-all-pkgs")
			}

			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			osArgs = append(osArgs, "--output", outputFile)
			osArgs = append(osArgs, tt.args.input)

			// Run "trivy convert"
			runTest(t, osArgs, tt.golden, outputFile, types.Format(tt.args.format), runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			})
		})
	}

}
