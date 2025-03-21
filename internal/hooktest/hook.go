package hooktest

import (
	"context"
	"errors"
	"testing"

	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

type testHook struct{}

func (*testHook) Name() string {
	return "test"
}

func (*testHook) Version() int {
	return 1
}

// RunHook implementation
func (*testHook) PreRun(ctx context.Context, opts flag.Options) error {
	if opts.GlobalOptions.ConfigFile == "bad-config" {
		return errors.New("bad pre-run")
	}
	return nil
}

func (*testHook) PostRun(ctx context.Context, opts flag.Options) error {
	if opts.GlobalOptions.ConfigFile == "bad-config" {
		return errors.New("bad post-run")
	}
	return nil
}

// ScanHook implementation
func (*testHook) PreScan(ctx context.Context, target *types.ScanTarget, options types.ScanOptions) error {
	if target.Name == "bad-pre" {
		return errors.New("bad pre-scan")
	}
	return nil
}

func (*testHook) PostScan(ctx context.Context, results types.Results) (types.Results, error) {
	for i, r := range results {
		if r.Target == "bad" {
			return nil, errors.New("bad")
		}
		for j := range r.Vulnerabilities {
			results[i].Vulnerabilities[j].References = []string{
				"https://example.com/post-scan",
			}
		}
	}
	return results, nil
}

// ReportHook implementation
func (*testHook) PreReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	if report.ArtifactName == "bad-report" {
		return errors.New("bad pre-report")
	}

	// Modify the report
	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			report.Results[i].Vulnerabilities[j].Title = "Modified by pre-report hook"
		}
	}
	return nil
}

func (*testHook) PostReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	if report.ArtifactName == "bad-report" {
		return errors.New("bad post-report")
	}

	// Modify the report
	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			report.Results[i].Vulnerabilities[j].Description = "Modified by post-report hook"
		}
	}
	return nil
}

func Init(t *testing.T) {
	h := &testHook{}
	extension.Register(h)
	t.Cleanup(func() {
		extension.Deregister(h.Name())
	})
}
