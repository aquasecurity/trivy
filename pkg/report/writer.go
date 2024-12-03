package report

import (
	"context"
	"io"
	"strings"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
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

// Write writes the result to output, format as passed in argument
func Write(ctx context.Context, report types.Report, option flag.Options) (err error) {
	output, cleanup, err := option.OutputWriter(ctx)
	if err != nil {
		return xerrors.Errorf("failed to create a file: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			err = multierror.Append(err, cerr)
		}
	}()

	// Compliance report
	if option.Compliance.Spec.ID != "" {
		return complianceWrite(ctx, report, option, output)
	}

	var writer Writer
	switch option.Format {
	case types.FormatTable:
		writer = &table.Writer{
			Output:               output,
			Severities:           option.Severities,
			Tree:                 option.DependencyTree,
			ShowSuppressed:       option.ShowSuppressed,
			IncludeNonFailures:   option.IncludeNonFailures,
			Trace:                option.Trace,
			LicenseRiskThreshold: option.LicenseRiskThreshold,
			IgnoredLicenses:      option.IgnoredLicenses,
		}
	case types.FormatJSON:
		writer = &JSONWriter{
			Output:         output,
			ListAllPkgs:    option.ListAllPkgs,
			ShowSuppressed: option.ShowSuppressed,
		}
	case types.FormatGitHub:
		writer = &github.Writer{
			Output:  output,
			Version: option.AppVersion,
		}
	case types.FormatCycloneDX:
		// TODO: support xml format option with cyclonedx writer
		writer = cyclonedx.NewWriter(output, option.AppVersion)
	case types.FormatSPDX, types.FormatSPDXJSON:
		writer = spdx.NewWriter(output, option.AppVersion, option.Format)
	case types.FormatTemplate:
		// We keep `sarif.tpl` template working for backward compatibility for a while.
		if strings.HasPrefix(option.Template, "@") && strings.HasSuffix(option.Template, "sarif.tpl") {
			log.Warn("Using `--template sarif.tpl` is deprecated. Please migrate to `--format sarif`. See https://github.com/aquasecurity/trivy/discussions/1571")
			writer = &SarifWriter{
				Output:  output,
				Version: option.AppVersion,
			}
			break
		}
		if writer, err = NewTemplateWriter(output, option.Template, option.AppVersion); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	case types.FormatSarif:
		target := ""
		if report.ArtifactType == artifact.TypeFilesystem {
			target = option.Target
		}
		writer = &SarifWriter{
			Output:  output,
			Version: option.AppVersion,
			Target:  target,
		}
	case types.FormatCosignVuln:
		writer = predicate.NewVulnWriter(output, option.AppVersion)
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	if err = writer.Write(ctx, report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	return nil
}

func complianceWrite(ctx context.Context, report types.Report, opt flag.Options, output io.Writer) error {
	complianceReport, err := cr.BuildComplianceReport([]types.Results{report.Results}, opt.Compliance)
	if err != nil {
		return xerrors.Errorf("compliance report build error: %w", err)
	}
	return cr.Write(ctx, complianceReport, cr.Option{
		Format:     opt.Format,
		Report:     opt.ReportFormat,
		Output:     output,
		Severities: opt.Severities,
	})
}

// Writer defines the result write operation
type Writer interface {
	Write(context.Context, types.Report) error
}
