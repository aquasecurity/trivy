//go:build integration

package integration

import (
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
		name   string
		args   args
		golden string
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
				tt.args.input,
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

			// Run "trivy convert"
			runTest(t, osArgs, tt.golden, types.Format(tt.args.format), runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: nil, // Do not use overrides - golden files are generated from this test as the canonical source
			})
		})
	}
}

// TestConvertCrypto tests that converting a JSON report with crypto findings gives the same
// report as a scan. Only the JSON report keeps the findings.
//
// Golden files are shared with TestTar.
func TestConvertCrypto(t *testing.T) {
	if *update {
		t.Skipf("Skipping TestConvertCrypto when -update flag is set. Golden files should be updated via TestTar.")
	}

	tests := []struct {
		name   string
		format types.Format
		golden string
	}{
		{
			name:   "cyclonedx",
			format: types.FormatCycloneDX,
			golden: goldenCryptoCDX,
		},
		{
			name:   "json",
			format: types.FormatJSON,
			golden: goldenCryptoJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{
				"convert",
				goldenCryptoJSON,
				"--cache-dir",
				t.TempDir(),
				"-q",
				"--format",
				string(tt.format),
			}

			runTest(t, osArgs, tt.golden, tt.format, runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
			})
		})
	}
}
