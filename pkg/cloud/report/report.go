package report

import (
	"context"
	"os"
	"sort"
	"time"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aquasecurity/tml"

	"github.com/aquasecurity/trivy/pkg/flag"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy/pkg/result"

	"github.com/aquasecurity/defsec/pkg/scan"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	tableFormat = "table"
)

// Report represents a kubernetes scan report
type Report struct {
	Provider        string
	AccountID       string
	Region          string
	Results         map[string]ResultsAtTime
	ServicesInScope []string
}

type ResultsAtTime struct {
	Results      types.Results
	CreationTime time.Time
}

func New(provider, accountID, region string, defsecResults scan.Results, scopedServices []string) *Report {
	return &Report{
		Provider:        provider,
		AccountID:       accountID,
		Results:         ConvertResults(defsecResults, provider, scopedServices),
		ServicesInScope: scopedServices,
		Region:          region,
	}
}

// Failed returns whether the aws report includes any "failed" results
func (r *Report) Failed() bool {
	for _, set := range r.Results {
		if set.Results.Failed() {
			return true
		}
	}
	return false
}

// Write writes the results in the give format
func Write(rep *Report, opt flag.Options, fromCache bool) error {

	var filtered []types.Result

	ctx := context.Background()

	// filter results
	for _, resultsAtTime := range rep.Results {
		for _, res := range resultsAtTime.Results {
			resCopy := res
			if err := result.Filter(
				ctx,
				&resCopy,
				opt.Severities,
				false,
				false,
				"",
				"",
				nil,
			); err != nil {
				return err
			}
			sort.Slice(resCopy.Misconfigurations, func(i, j int) bool {
				return resCopy.Misconfigurations[i].CauseMetadata.Resource < resCopy.Misconfigurations[j].CauseMetadata.Resource
			})
			filtered = append(filtered, resCopy)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Target < filtered[j].Target
	})

	base := types.Report{
		ArtifactName: rep.AccountID,
		ArtifactType: ftypes.ArtifactAWSAccount,
		Results:      filtered,
	}

	switch opt.Format {
	case tableFormat:

		// ensure color/formatting is disabled for pipes/non-pty
		var useANSI bool
		if opt.Output == os.Stdout {
			if o, err := os.Stdout.Stat(); err == nil {
				useANSI = (o.Mode() & os.ModeCharDevice) == os.ModeCharDevice
			}
		}
		if !useANSI {
			tml.DisableFormatting()
		}

		switch {
		case len(opt.Services) == 1 && opt.ARN == "":
			if err := writeResourceTable(rep, filtered, opt.Output, opt.Services[0]); err != nil {
				return err
			}
		case len(opt.Services) == 1 && opt.ARN != "":
			if err := writeResultsForARN(rep, filtered, opt.Output, opt.Services[0], opt.ARN, opt.Severities); err != nil {
				return err
			}
		default:
			if err := writeServiceTable(rep, filtered, opt.Output); err != nil {
				return err
			}
		}

		// render cache info
		if fromCache {
			_ = tml.Fprintf(opt.Output, "\n<blue>This scan report was loaded from cached results. If you'd like to run a fresh scan, use --update-cache.</blue>\n")
		}

		return nil
	default:
		return report.Write(base, pkgReport.Option{
			Format:             opt.Format,
			Output:             opt.Output,
			Severities:         opt.Severities,
			OutputTemplate:     opt.Template,
			IncludeNonFailures: opt.IncludeNonFailures,
			Trace:              opt.Trace,
		})
	}
}
