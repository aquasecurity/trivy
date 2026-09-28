package report

import (
	"context"
	"io"
	"net/url"
	"strings"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/extension"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
	// Call pre-report hooks
	if err := extension.PreReport(ctx, &report, option); err != nil {
		return xerrors.Errorf("pre report error: %w", err)
	}

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

	writer, err := initWriter(output, report, option)
	if err != nil {
		return err
	}

	if err = writer.Write(ctx, report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	// Call post-report hooks
	if err := extension.PostReport(ctx, &report, option); err != nil {
		return xerrors.Errorf("post report error: %w", err)
	}

	return nil
}

func initWriter(output io.Writer, report types.Report, option flag.Options) (Writer, error) {
	switch option.Format {
	case types.FormatTable:
		return table.NewWriter(table.Options{
			Scanners:             option.Scanners,
			Output:               output,
			Severities:           option.Severities,
			Tree:                 option.DependencyTree,
			ShowSuppressed:       option.ShowSuppressed,
			IncludeNonFailures:   option.IncludeNonFailures,
			Trace:                option.RegoOptions.Trace,
			RenderCause:          option.RenderCause,
			LicenseRiskThreshold: option.LicenseRiskThreshold,
			IgnoredLicenses:      option.IgnoredLicenses,
			TableModes:           option.TableModes,
		}), nil
	case types.FormatJSON:
		return &JSONWriter{
			Output:         output,
			ListAllPkgs:    option.ListAllPkgs,
			ShowSuppressed: option.ShowSuppressed,
		}, nil
	case types.FormatGitHub:
		return &github.Writer{
			Output:  output,
			Version: option.AppVersion,
		}, nil
	case types.FormatCycloneDX:
		// TODO: support xml format option with cyclonedx writer
		return cyclonedx.NewWriter(output, option.AppVersion), nil
	case types.FormatSPDX, types.FormatSPDXJSON:
		return spdx.NewWriter(output, option.AppVersion, option.Format), nil
	case types.FormatTemplate:
		// We keep `sarif.tpl` template working for backward compatibility for a while.
		if strings.HasPrefix(option.Template, "@") && strings.HasSuffix(option.Template, "sarif.tpl") {
			log.Warn("Using `--template sarif.tpl` is deprecated. Please migrate to `--format sarif`. See https://github.com/aquasecurity/trivy/discussions/1571")
			return &SarifWriter{
				Output:  output,
				Version: option.AppVersion,
			}, nil
		}
		writer, err := NewTemplateWriter(output, option.Template, option.AppVersion)
		if err != nil {
			return nil, xerrors.Errorf("failed to initialize template writer: %w", err)
		}
		return writer, nil
	case types.FormatSarif:
		return &SarifWriter{
			Output:  output,
			Version: option.AppVersion,
			Target:  sarifTarget(report.ArtifactType, option.Target),
		}, nil
	case types.FormatCosignVuln:
		return predicate.NewVulnWriter(output, option.AppVersion), nil
	default:
		return nil, xerrors.Errorf("unknown format: %v", option.Format)
	}
}

func sarifTarget(artifactType ftypes.ArtifactType, target string) string {
	if artifactType != ftypes.TypeFilesystem && artifactType != ftypes.TypeRepository {
		return ""
	}
	// Keep credentials out of the report (e.g. ROOTPATH in SARIF).
	if u, err := url.Parse(target); err == nil && u.User != nil {
		redacted := *u
		redacted.User = nil
		return redacted.String()
	}
	return target
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
