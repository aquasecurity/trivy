package report

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aquasecurity/trivy/pkg/flag"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy/pkg/result"

	"github.com/aquasecurity/defsec/pkg/scan"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	tableFormat = "table"
	jsonFormat  = "json"
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
		Results:         convertResults(defsecResults, provider, scopedServices),
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
			filtered = append(filtered, resCopy)
		}
	}

	base := types.Report{
		Results: filtered,
	}

	switch opt.Format {
	case jsonFormat:
		return json.NewEncoder(opt.Output).Encode(rep)
	case tableFormat:
		switch {
		case len(opt.Services) == 1 && opt.ARN == "":
			return writeResourceTable(rep, filtered, opt.Output, fromCache, opt.Services[0])
		case len(opt.Services) == 1 && opt.ARN != "":
			return writeResultsForARN(rep, filtered, opt.Output, fromCache, opt.Services[0], opt.ARN, opt.Severities)
		default:
			return writeServiceTable(rep, filtered, opt.Output, fromCache)
		}
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

func (r *Report) GetResultsForService(service string) (*ResultsAtTime, error) {
	if set, ok := r.Results[service]; ok {
		return &set, nil
	}
	for _, scoped := range r.ServicesInScope {
		if scoped == service {
			return &ResultsAtTime{
				Results:      nil,
				CreationTime: time.Now(),
			}, nil
		}
	}
	return nil, fmt.Errorf("service %q not found", service)
}

func (r *Report) AddResultsForService(service string, results types.Results, creation time.Time) {
	r.Results[service] = ResultsAtTime{
		Results:      results,
		CreationTime: creation,
	}
	for _, exists := range r.ServicesInScope {
		if exists == service {
			return
		}
	}
	r.ServicesInScope = append(r.ServicesInScope, service)
}
