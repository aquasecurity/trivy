package report

import (
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	SchemaVersion = 2
)

// Now returns the current time
var Now = time.Now

type Option struct {
	Format         string
	Output         io.Writer
	Severities     []dbTypes.Severity
	OutputTemplate string
	AppVersion     string

	// For misconfigurations
	IncludeNonFailures bool
	Trace              bool
}

// Write writes the result to output, format as passed in argument
func Write(report types.Report, option Option) error {
	var writer Writer
	switch option.Format {
	case "table":
		writer = &TableWriter{
			Output:             option.Output,
			Severities:         option.Severities,
			ShowMessageOnce:    &sync.Once{},
			IncludeNonFailures: option.IncludeNonFailures,
			Trace:              option.Trace,
		}
	case "json":
		writer = &JSONWriter{Output: option.Output}
	case "cyclonedx":
		// TODO: support xml format option with cyclonedx writer
		writer = cyclonedx.NewWriter(option.Output, option.AppVersion)
	case "template":
		// We keep `sarif.tpl` template working for backward compatibility for a while.
		if strings.HasPrefix(option.OutputTemplate, "@") && filepath.Base(option.OutputTemplate) == "sarif.tpl" {
			log.Logger.Warn("Using `--template sarif.tpl` is deprecated. Please migrate to `--format sarif`. See https://github.com/aquasecurity/trivy/discussions/1571")
			writer = SarifWriter{Output: option.Output, Version: option.AppVersion}
			break
		}
		var err error
		if writer, err = NewTemplateWriter(option.Output, option.OutputTemplate); err != nil {
			return xerrors.Errorf("failed to initialize template writer: %w", err)
		}
	case "sarif":
		writer = SarifWriter{Output: option.Output, Version: option.AppVersion}
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	if err := writer.Write(report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}
	return nil
}

// Writer defines the result write operation
type Writer interface {
	Write(types.Report) error
}
