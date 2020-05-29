package config

import (
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

type ReportConfig struct {
	Format   string
	Template string

	IgnoreFile    string
	IgnoreUnfixed bool
	ExitCode      int

	// these variables are not exported
	vulnType   string
	output     string
	severities string

	// these variables are populated by Init()
	VulnType   []string
	Output     *os.File
	Severities []dbTypes.Severity
}

func NewReportConfig(c *cli.Context) ReportConfig {
	return ReportConfig{
		output:   c.String("output"),
		Format:   c.String("format"),
		Template: c.String("template"),

		vulnType:      c.String("vuln-type"),
		severities:    c.String("severity"),
		IgnoreFile:    c.String("ignorefile"),
		IgnoreUnfixed: c.Bool("ignore-unfixed"),
		ExitCode:      c.Int("exit-code"),
	}
}

func (c *ReportConfig) Init(logger *zap.SugaredLogger) (err error) {
	if c.Template != "" {
		if c.Format == "" {
			logger.Warn("--template is ignored because --format template is not specified. Use --template option with --format template option.")
		} else if c.Format != "template" {
			logger.Warnf("--template is ignored because --format %s is specified. Use --template option with --format template option.", c.Format)
		}
	}
	if c.Format == "template" && c.Template == "" {
		logger.Warn("--format template is ignored because --template not is specified. Specify --template option when you use --format template.")
	}

	c.Severities = c.splitSeverity(logger, c.severities)
	c.VulnType = strings.Split(c.vulnType, ",")

	// for testability
	c.severities = ""
	c.vulnType = ""

	c.Output = os.Stdout
	if c.output != "" {
		if c.Output, err = os.Create(c.output); err != nil {
			return xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

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
