//go:build integration

package integration

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
)

// TestConvert tests the convert command with various output formats.
//
// NOTE: This test CAN update golden files with the -update flag because the golden files
// used here are not shared with other tests. These format conversion golden files are unique
// to this test and should be updated here.
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
				input:  goldenNPM,
				format: "cyclonedx",
			},
			golden: goldenNPMCycloneDX,
		},
		{
			name: "npm without package UID",
			args: args{
				input:  "testdata/fixtures/convert/npm.json.golden",
				format: "cyclonedx",
			},
			golden: goldenNPMCycloneDX,
		},
		{
			name: "npm with suppressed vulnerability",
			args: args{
				input:          goldenConvertNPMWithSuppressed,
				format:         "json",
				showSuppressed: true,
				listAllPkgs:    true,
			},
			golden: goldenConvertNPMWithSuppressed,
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

			if !tt.args.listAllPkgs {
				osArgs = append(osArgs, "--list-all-pkgs=false")
			}

			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			osArgs = append(osArgs, "--output", outputFile, tt.args.input)

			// Run "trivy convert"
			runTest(t, osArgs, tt.golden, outputFile, types.Format(tt.args.format), runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			})
		})
	}

}
