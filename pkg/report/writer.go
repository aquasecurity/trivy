package report

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	cr "github.com/deepfactor-io/trivy/pkg/compliance/report"
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/flag"
	"github.com/deepfactor-io/trivy/pkg/log"
	"github.com/deepfactor-io/trivy/pkg/report/cyclonedx"
	"github.com/deepfactor-io/trivy/pkg/report/github"
	"github.com/deepfactor-io/trivy/pkg/report/predicate"
	"github.com/deepfactor-io/trivy/pkg/report/spdx"
	"github.com/deepfactor-io/trivy/pkg/report/table"
	"github.com/deepfactor-io/trivy/pkg/types"
)

const (
	SchemaVersion = 2
)

// type Option struct {
// 	AppVersion   string
// 	DfctlVersion string
// 	DfctlImage   string

// 	Format         string
// 	Report         string
// 	Output         io.Writer
// 	Tree           bool
// 	Severities     []dbTypes.Severity
// 	OutputTemplate string
// 	Compliance     spec.ComplianceSpec

// 	// For misconfigurations
// 	IncludeNonFailures bool
// 	Trace              bool

// 	// For licenses
// 	LicenseRiskThreshold int
// 	IgnoredLicenses      []string
// }

// Write writes the result to output, format as passed in argument
func Write(ctx context.Context, report types.Report, option flag.Options) (err error) {
	output, cleanup, err := option.OutputWriter(ctx)
	if err != nil {
		return xerrors.Errorf("failed to create a file: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	// Compliance report
	if option.Compliance.Spec.ID != "" {
		return complianceWrite(report, option, output)
	}

	var writer Writer
	switch option.Format {
	case types.FormatTable:
		writer = &table.Writer{
			Output:               output,
			Severities:           option.Severities,
			Tree:                 option.DependencyTree,
			ShowMessageOnce:      &sync.Once{},
			IncludeNonFailures:   option.IncludeNonFailures,
			Trace:                option.Trace,
			LicenseRiskThreshold: option.LicenseRiskThreshold,
			IgnoredLicenses:      option.IgnoredLicenses,
		}
	case types.FormatJSON:
		writer = &JSONWriter{Output: output}
	case types.FormatGitHub:
		writer = &github.Writer{
			Output:     output,
			Version:    option.AppVersion,
			DfctlImage: option.DfctlImage,
		}
	case types.FormatCycloneDX:
		// TODO: support xml format option with cyclonedx writer
		writer = cyclonedx.NewWriter(output, option.DfctlVersion)
	case types.FormatSPDX, types.FormatSPDXJSON:
		writer = spdx.NewWriter(output, option.AppVersion, option.Format)
	case types.FormatTemplate:
		// We keep `sarif.tpl` template working for backward compatibility for a while.
		if strings.HasPrefix(option.Template, "@") && strings.HasSuffix(option.Template, "sarif.tpl") {
			log.Logger.Warn("Using `--template sarif.tpl` is deprecated. Please migrate to `--format sarif`. See https://github.com/aquasecurity/trivy/discussions/1571")
			writer = &SarifWriter{
				Output:  output,
				Version: option.AppVersion,
			}
			break
		}
		var err error
		if writer, err = NewTemplateWriter(output, option.Template, option.AppVersion); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	case types.FormatSarif:
		target := ""
		if report.ArtifactType == ftypes.ArtifactFilesystem {
			target = option.Target
		}
		writer = &SarifWriter{
			Output:       output,
			Version:      option.AppVersion,
			Target:       target,
			ScannerImage: option.DfctlImage,
		}
	case types.FormatCosignVuln:
		writer = predicate.NewVulnWriter(output, option.AppVersion)
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	if err = writer.Write(report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	return nil
}

func complianceWrite(report types.Report, opt flag.Options, output io.Writer) error {
	complianceReport, err := cr.BuildComplianceReport([]types.Results{report.Results}, opt.Compliance)
	if err != nil {
		return xerrors.Errorf("compliance report build error: %w", err)
	}
	return cr.Write(complianceReport, cr.Option{
		Format:     opt.Format,
		Report:     opt.ReportFormat,
		Output:     output,
		Severities: opt.Severities,
	})
}

// Writer defines the result write operation
type Writer interface {
	Write(types.Report) error
}
