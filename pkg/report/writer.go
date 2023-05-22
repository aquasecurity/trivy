package report

import (
	"strings"
	"sync"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/report/github"
	"github.com/aquasecurity/trivy/pkg/report/predicate"
	"github.com/aquasecurity/trivy/pkg/report/spdx"
	"github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	SchemaVersion = 2
)

// Writer defines the result write operation
type Writer interface {
	Write(types.Report) error
}

type Option struct {
	AppVersion string

	Outputs    types.Outputs
	Report     string
	Tree       bool
	Severities []dbTypes.Severity
	Compliance spec.ComplianceSpec

	// For misconfigurations
	IncludeNonFailures bool
	Trace              bool

	// For licenses
	LicenseRiskThreshold int
	IgnoredLicenses      []string
}

// Write writes the result to output, format as passed in argument
func Write(report types.Report, option Option) error {
	// Compliance report
	if option.Compliance.Spec.ID != "" {
		return complianceWrite(report, option)
	}

	for _, output := range option.Outputs {
		if err := write(report, output, option); err != nil {
			return xerrors.Errorf("failed to write results: %w", err)
		}
	}
	return nil
}

func write(report types.Report, output types.Output, option Option) error {
	// Set up the output writer, file or stdout
	dest, err := output.Writer()
	if err != nil {
		return err
	}
	defer dest.Close()

	var writer Writer
	switch output.Format {
	case types.FormatTable:
		writer = &table.Writer{
			Output:               dest,
			Severities:           option.Severities,
			Tree:                 option.Tree,
			ShowMessageOnce:      &sync.Once{},
			IncludeNonFailures:   option.IncludeNonFailures,
			Trace:                option.Trace,
			LicenseRiskThreshold: option.LicenseRiskThreshold,
			IgnoredLicenses:      option.IgnoredLicenses,
		}
	case types.FormatJSON:
		writer = &JSONWriter{Output: dest}
	case types.FormatGitHub:
		writer = &github.Writer{
			Output:  dest,
			Version: option.AppVersion,
		}
	case types.FormatCycloneDX:
		// TODO: support xml format option with cyclonedx writer
		writer = cyclonedx.NewWriter(dest, option.AppVersion)
	case types.FormatSPDX, types.FormatSPDXJSON:
		writer = spdx.NewWriter(dest, option.AppVersion, output.Format)
	case types.FormatTemplate:
		// We keep `sarif.tpl` template working for backward compatibility for a while.
		if strings.HasPrefix(output.Template, "@") && strings.HasSuffix(output.Template, "sarif.tpl") {
			log.Logger.Warn("Using `--template sarif.tpl` is deprecated. Please migrate to `--format sarif`. See https://github.com/aquasecurity/trivy/discussions/1571")
			writer = &SarifWriter{
				Output:  dest,
				Version: option.AppVersion,
			}
			break
		}
		if writer, err = NewTemplateWriter(dest, output.Template); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	case types.FormatSarif:
		writer = &SarifWriter{
			Output:  dest,
			Version: option.AppVersion,
		}
	case types.FormatCosignVuln:
		writer = predicate.NewVulnWriter(dest, option.AppVersion)
	default:
		return xerrors.Errorf("unknown format: %v", output.Format)
	}

	if err = writer.Write(report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	return nil
}

func complianceWrite(report types.Report, opt Option) error {
	complianceReport, err := cr.BuildComplianceReport([]types.Results{report.Results}, opt.Compliance)
	if err != nil {
		return xerrors.Errorf("compliance report build error: %w", err)
	}
	return cr.Write(complianceReport, cr.Option{
		Report:     opt.Report,
		Output:     opt.Outputs[0], // TODO: support multiple outputs
		Severities: opt.Severities,
	})
}
