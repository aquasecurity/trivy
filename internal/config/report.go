package config

import (
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

// ReportConfig holds the config for reporting scan results
type ReportConfig struct {
	IgnoreFile    string
	IgnoreUnfixed bool
	ExitCode      int
	IgnorePolicy  string

	// these variables are not exported
	vulnType   string
	output     string
	severities string
	format     string
	template   string

	// these variables are populated by Init()
	VulnType   []string
	Severities []dbTypes.Severity
	Formats    []MappedFormat
}

// MappedFormat holds the mapped output and template for multi-format report
type MappedFormat struct {
	Format   string
	Output   *os.File
	Template string
}

// DefaultFormat holds the default mapped output and template for multi-format report
var DefaultFormat = MappedFormat{
	Format:   "table",
	Output:   os.Stdout,
	Template: "",
}

// NewReportConfig is the factory method to return ReportConfig
func NewReportConfig(c *cli.Context) ReportConfig {
	return ReportConfig{
		output:       c.String("output"),
		format:       c.String("format"),
		template:     c.String("template"),
		IgnorePolicy: c.String("ignore-policy"),

		vulnType:      c.String("vuln-type"),
		severities:    c.String("severity"),
		IgnoreFile:    c.String("ignorefile"),
		IgnoreUnfixed: c.Bool("ignore-unfixed"),
		ExitCode:      c.Int("exit-code"),
	}
}

// Init initializes the ReportConfig
func (c *ReportConfig) Init(logger *zap.SugaredLogger) (err error) {
	var format, template []string
	var output []*os.File

	if c.format == "" {
		if c.template != "" {
			logger.Warn("--template is ignored because --format template is not specified. Use --template option with --format template option.")
		}
		c.Formats = []MappedFormat{DefaultFormat}
	} else {
		format = strings.Split(c.format, ",")
		output, err = c.mapOutput(format, logger)
		if err != nil {
			return err
		}
		template = c.mapTemplate(format, logger)
	}

	for i := range format {
		if format[i] == "template" && template[i] == "" {
			continue
		}

		c.Formats = append(c.Formats, MappedFormat{
			Format:   format[i],
			Output:   output[i],
			Template: template[i],
		})
	}

	c.Severities = c.splitSeverity(logger, c.severities)
	c.VulnType = strings.Split(c.vulnType, ",")

	// for testability
	c.severities = ""
	c.vulnType = ""
	c.output = ""
	c.template = ""
	c.format = ""

	return nil
}

func (c *ReportConfig) splitSeverity(logger *zap.SugaredLogger, severity string) []dbTypes.Severity {
	logger.Debugf("Severities: %s", severity)
	var severities []dbTypes.Severity
	for _, s := range strings.Split(severity, ",") {
		severity, err := dbTypes.NewSeverity(s)
		if err != nil {
			logger.Warnf("unknown severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	return severities
}

// mapFormat maps format and output for multi-format report
func (c *ReportConfig) mapOutput(format []string, logger *zap.SugaredLogger) (output []*os.File, err error) {
	for _, v := range strings.Split(c.output, ",") {
		var out *os.File
		if v != "" && v != "stdout" {
			if out, err = os.Create(v); err != nil {
				return output, xerrors.Errorf("failed to create an output file: %w", err)
			}
		} else {
			out = os.Stdout
		}
		output = append(output, out)
	}

	for i := len(output); i < len(format); i++ {
		output = append(output, os.Stdout)
	}

	return output, nil
}

// mapFormat maps format and template for multi-format report
func (c *ReportConfig) mapTemplate(format []string, logger *zap.SugaredLogger) (template []string) {
	var isTemplate bool
	formats := make(map[string]struct{})

	for _, f := range format {
		_, ok := formats[f]
		if ok {
			template = append(template, "")
			logger.Warnf("--format %s is ignored because it has been specified.", f)
			continue
		}
		formats[f] = struct{}{}

		if f == "template" {
			isTemplate = true
			if c.template == "" {
				logger.Warn("--format template is ignored because --template is not specified. Specify --template option when you use --format template.")
			} else {
				template = append(template, c.template)
				continue
			}
		}
		template = append(template, "")
	}
	if !isTemplate && c.template != "" {
		logger.Warnf("--template is ignored because --format %s is specified. Use --template option with --format template option.", format)
	}

	return template
}
