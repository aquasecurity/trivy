package artifact

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func TestPerformance(t *testing.T) {
	args := []string{}
	flgs := &flag.Flags{}
	globalFlags := &flag.GlobalFlagGroup{}

	options, _ := flgs.ToOptions("perf-version", args, globalFlags, os.Stdout)
	options.ScanOptions.Target = "~/demo-data/jboss/"
	options.Slow = true
	options.Timeout = time.Hour
	options.CacheDir = utils.DefaultCacheDir()
	options.Format = "json"
	options.Output = os.Stdout
	options.SecurityChecks = []string{"vuln"}

	err := Run(context.Background(), options, TargetFilesystem)
	if err != nil {
		t.Errorf("error: %v", err)
	}
}
