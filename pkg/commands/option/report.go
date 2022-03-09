package option

import (
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

// ReportOption holds the options for reporting scan results
type ReportOption struct {
	Format   string
	Template string

	IgnoreFile    string
	IgnoreUnfixed bool
	ExitCode      int
	IgnorePolicy  string

	// these variables are not exported
	vulnType       string
	securityChecks string
	output         string
	severities     string

	// these variables are populated by Init()
	VulnType       []string
	SecurityChecks []string
	Output         io.Writer
	Severities     []dbTypes.Severity
	ListAllPkgs    bool
}

// NewReportOption is the factory method to return ReportOption
func NewReportOption(c *cli.Context) ReportOption {
	return ReportOption{
		output:       c.String("output"),
		Format:       c.String("format"),
		Template:     c.String("template"),
		IgnorePolicy: c.String("ignore-policy"),

		vulnType:       c.String("vuln-type"),
		securityChecks: c.String("security-checks"),
		severities:     c.String("severity"),
		IgnoreFile:     c.String("ignorefile"),
		IgnoreUnfixed:  c.Bool("ignore-unfixed"),
		ExitCode:       c.Int("exit-code"),
		ListAllPkgs:    c.Bool("list-all-pkgs"),
	}
}

// Init initializes the ReportOption
func (c *ReportOption) Init(output io.Writer, logger *zap.SugaredLogger) error {
	if c.Template != "" {
		if c.Format == "" {
			logger.Warn("'--template' is ignored because '--format template' is not specified. Use '--template' option with '--format template' option.")
		} else if c.Format != "template" {
			logger.Warnf("'--template' is ignored because '--format %s' is specified. Use '--template' option with '--format template' option.", c.Format)
		}
	} else {
		if c.Format == "template" {
			logger.Warn("'--format template' is ignored because '--template' is not specified. Specify '--template' option when you use '--format template'.")
		}
	}

	// "--list-all-pkgs" option is unavailable with "--format table".
	// If user specifies "--list-all-pkgs" with "--format table", we should warn it.
	if c.ListAllPkgs && c.Format == "table" {
		logger.Warn(`"--list-all-pkgs" cannot be used with "--format table". Try "--format json" or other formats.`)
	}

	if c.forceListAllPkgs(logger) {
		c.ListAllPkgs = true
	}

	c.Severities = splitSeverity(logger, c.severities)

	if err := c.populateVulnTypes(); err != nil {
		return xerrors.Errorf("vuln type: %w", err)
	}

	if err := c.populateSecurityChecks(); err != nil {
		return xerrors.Errorf("security checks: %w", err)
	}

	// for testability
	c.severities = ""
	c.vulnType = ""
	c.securityChecks = ""

	// The output is os.Stdout by default
	if c.output != "" {
		var err error
		if output, err = os.Create(c.output); err != nil {
			return xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

	c.Output = output

	return nil
}

func (c *ReportOption) populateVulnTypes() error {
	if c.vulnType == "" {
		return nil
	}

	for _, v := range strings.Split(c.vulnType, ",") {
		if types.NewVulnType(v) == types.VulnTypeUnknown {
			return xerrors.Errorf("unknown vulnerability type (%s)", v)
		}
		c.VulnType = append(c.VulnType, v)
	}
	return nil
}

func (c *ReportOption) populateSecurityChecks() error {
	if c.securityChecks == "" {
		return nil
	}

	for _, v := range strings.Split(c.securityChecks, ",") {
		if types.NewSecurityCheck(v) == types.SecurityCheckUnknown {
			return xerrors.Errorf("unknown security check (%s)", v)
		}
		c.SecurityChecks = append(c.SecurityChecks, v)
	}
	return nil
}

func (c *ReportOption) forceListAllPkgs(logger *zap.SugaredLogger) bool {
	if c.Format == "cyclonedx" && !c.ListAllPkgs {
		logger.Debugf("'--format cyclonedx' automatically enables '--list-all-pkgs'.")
		return true
	}
	return false
}

func splitSeverity(logger *zap.SugaredLogger, severity string) []dbTypes.Severity {
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
