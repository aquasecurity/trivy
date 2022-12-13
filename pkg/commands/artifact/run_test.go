package artifact

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/go-containerregistry/cmd/crane/cmd"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func TestCanonicalVersion(t *testing.T) {
	tests := []struct {
		title string
		input string
		want  string
	}{
		{
			title: "good way",
			input: "0.34.0",
			want:  "v0.34",
		},
		{
			title: "version with v - isn't right semver version",
			input: "v0.34.0",
			want:  devVersion,
		},
		{
			title: "dev version",
			input: devVersion,
			want:  devVersion,
		},
		{
			title: "pre-release",
			input: "v0.34.0-beta1+snapshot-1",
			want:  devVersion,
		},
		{
			title: "no version",
			input: "",
			want:  devVersion,
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			got := canonicalVersion(test.input)
			require.Equal(t, test.want, got)
		})
	}
}

func TestPerformance(t *testing.T) {
	args := []string{}
	flgs := &flag.Flags{}
	globalFlags := &flag.GlobalFlagGroup{}

	options, _ := flgs.ToOptions(cmd.Version, args, globalFlags, os.Stdout)
	options.ScanOptions.Target = "jboss/wildfly:latest"
	options.Slow = true
	options.Timeout = time.Hour
	options.CacheDir = utils.DefaultCacheDir()
	options.Format = "json"
	options.Output = os.Stdout
	options.SecurityChecks = []string{"vuln"}

	err := Run(context.Background(), options, TargetContainerImage)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}
