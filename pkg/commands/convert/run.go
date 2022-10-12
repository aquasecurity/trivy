package convert

import (
	"context"
	"io/ioutil"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Run(ctx context.Context, opts flag.Options) (err error) {
	//open file
	jsonFile, err := os.Open(opts.ConvertOptions.Source)
	defer jsonFile.Close()
	if err != nil {
		return xerrors.Errorf("failed to open `%s`: %w", opts.Source, err)
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)
	r, _ := report.Read(byteValue)
	log.Logger.Debug("Filtering report")
	r, err = report.Filter(ctx, r, types.ResultFilters{
		Severities:         opts.Severities,
		IgnoreUnfixed:      opts.IgnoreUnfixed,
		IncludeNonFailures: opts.IncludeNonFailures,
		IgnoredFile:        opts.IgnoreFile,
		PolicyFile:         opts.IgnorePolicy,
		IgnoredLicenses:    opts.IgnoredLicenses,
	})
	if err != nil {
		return xerrors.Errorf("unable to filter vulnerabilities: %w", err)
	}
	log.Logger.Debug("Writing report to output...")
	if err := report.Write(r, report.Option{
		AppVersion:         opts.AppVersion,
		Format:             opts.Format,
		Output:             opts.Output,
		Tree:               opts.DependencyTree,
		Severities:         opts.Severities,
		OutputTemplate:     opts.Template,
		IncludeNonFailures: opts.IncludeNonFailures,
		Trace:              opts.Trace,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	if opts.ExitCode != 0 && r.Results.Failed() {
		os.Exit(opts.ExitCode)
	}
	return nil
}
