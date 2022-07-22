package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/aquasecurity/defsec/pkg/scan"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
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
func Write(report *Report, option Option) error {
	switch option.Format {
	case jsonFormat:
		return json.NewEncoder(option.Output).Encode(report)
	case tableFormat:
		switch option.ReportLevel {
		case LevelService:
			return writeServiceTable(report, option)
		case LevelResource:
			return writeResourceTable(report, option)
		case LevelResult:
			return writeResultsForARN(report, option)
		default:
			return fmt.Errorf("invalid level: %d", option.ReportLevel)
		}

	default:
		return fmt.Errorf(`unknown format %q. Use "json" or "table"`, option.Format)
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
