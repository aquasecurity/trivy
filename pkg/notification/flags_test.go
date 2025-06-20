package notification

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestFlagExtraction(t *testing.T) {
	tests := []struct {
		name             string
		command          string
		commandArgs      []string // essentially the command line arguments passed to the CLI
		expected         string
		ignoreParseError bool
	}{
		{
			name:        "valid flags extracted",
			command:     "image",
			commandArgs: []string{"--severity", "CRITICAL", "--scanners", "vuln,misconfig", "--pkg-types", "library", "--pkg-relationships", "direct,root", "nginx"},
			expected:    "--pkg-types=library --pkg-relationships=direct,root --severity=CRITICAL --scanners=vuln,misconfig",
		},
		{
			name:        "no flags to be extracted",
			commandArgs: []string{"image", "nginx"},
			expected:    "",
		},
		{
			name:             "invalid flag is still included",
			commandArgs:      []string{"image", "--invalid-flag", "nginx"},
			expected:         "",
			ignoreParseError: true,
		},
		{
			name:        "multiple flags with same name",
			commandArgs: []string{"image", "--severity", "MEDIUM", "--severity", "CRITICAL", "--scanners", "vuln", "--scanners", "misconfig", "nginx"},
			expected:    "--severity=MEDIUM,CRITICAL --scanners=vuln,misconfig",
		},
		{
			name:        "fs with discrete valued flags",
			commandArgs: []string{"fs", "--severity", "HIGH", "--vex", "repo", "--vuln-severity-source", "nvd,debian", "../trivy-ci-test"},
			expected:    "--severity=HIGH --vex=****** --vuln-severity-source=nvd,debian",
		},
		{
			name:        "use short and long flags for same option",
			commandArgs: []string{"image", "--severity", "LOW", "-s", "HIGH", "nginx"},
			expected:    "--severity=LOW,HIGH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := getOptionsForArgs(t, tt.commandArgs, tt.ignoreParseError)
			cobraFlags := getUsedFlags(opts)
			assert.Equal(t, tt.expected, cobraFlags)
		})
	}
}

// getOptionsForArgs uses a basic command to parse the flags so we can generate
// an options object from it
func getOptionsForArgs(t *testing.T, commandArgs []string, ignoreParseError bool) *flag.Options {
	flags := flag.Flags{
		flag.NewGlobalFlagGroup(),
		flag.NewImageFlagGroup(),
		flag.NewMisconfFlagGroup(),
		flag.NewPackageFlagGroup(),
		flag.NewReportFlagGroup(),
		flag.NewScanFlagGroup(),
		flag.NewVulnerabilityFlagGroup(),
	}

	// simple command to facilitate flag parsing
	cmd := &cobra.Command{}
	flags.AddFlags(cmd)
	err := cmd.ParseFlags(commandArgs)
	if !ignoreParseError {
		require.NoError(t, err)
	}

	require.NoError(t, flags.Bind(cmd))
	opts, err := flags.ToOptions(commandArgs)
	require.NoError(t, err)
	return &opts
}
