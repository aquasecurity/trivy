package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aquasecurity/trivy/pkg/flag"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy/pkg/result"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aquasecurity/defsec/pkg/scan"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	tableFormat = "table"
	jsonFormat  = "json"
)

type Option struct {
	Format      string
	Type        string
	Output      io.Writer
	Severities  []dbTypes.Severity
	FromCache   bool
	ReportLevel Level
	Service     string
	ARN         string
}

type Level uint8

const (
	LevelService Level = iota
	LevelResource
	LevelResult
)

// Report represents a kubernetes scan report
type Report struct {
	Provider        string
	AccountID       string
	Region          string
	Results         map[string]ResultAtTime
	ServicesInScope []string
}

type ResultAtTime struct {
	Result       types.Result
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
		if (types.Results{set.Result}).Failed() {
			return true
		}
	}
	return false
}

// Write writes the results in the give format
func Write(rep *Report, baseOptions flag.Options, reportOptions Option) error {

	var filtered []types.Result

	ctx := context.Background()

	// filter results
	for _, res := range rep.Results {
		resCopy := res.Result
		if err := result.Filter(
			ctx,
			&resCopy,
			reportOptions.Severities,
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

	base := types.Report{
		Results: filtered,
	}

	switch reportOptions.Format {
	case jsonFormat:
		return json.NewEncoder(reportOptions.Output).Encode(rep)
	case tableFormat:
		switch reportOptions.ReportLevel {
		case LevelService:
			return writeServiceTable(rep, reportOptions)
		case LevelResource:
			return writeResourceTable(rep, reportOptions)
		case LevelResult:
			return writeResultsForARN(rep, reportOptions)
		default:
			return fmt.Errorf("invalid level: %d", reportOptions.ReportLevel)
		}
	default:
		return report.Write(base, pkgReport.Option{
			Output:             baseOptions.Output,
			Severities:         baseOptions.Severities,
			IncludeNonFailures: baseOptions.IncludeNonFailures,
			Trace:              baseOptions.Trace,
			OutputTemplate:     baseOptions.Template,
		})
	}
}

func (r *Report) GetResultForService(service string) (*ResultAtTime, error) {
	if set, ok := r.Results[service]; ok {
		return &set, nil
	}
	for _, scoped := range r.ServicesInScope {
		if scoped == service {
			return &ResultAtTime{
				Result: types.Result{
					Target: service,
					Class:  types.ClassConfig,
					Type:   ftypes.Cloud,
				},
				CreationTime: time.Now(),
			}, nil
		}
	}
	return nil, fmt.Errorf("service %q not found", service)
}

func (r *Report) AddResultForService(service string, result types.Result, creation time.Time) {
	r.Results[service] = ResultAtTime{
		Result:       result,
		CreationTime: creation,
	}
	for _, exists := range r.ServicesInScope {
		if exists == service {
			return
		}
	}
	r.ServicesInScope = append(r.ServicesInScope, service)
}
