package flag

import (
	"strings"

	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

// e.g. config yaml:
//
//	format: table
//	dependency-tree: true
//	severity: HIGH,CRITICAL
var (
	FormatFlag = Flag{
		Name:       "format",
		ConfigName: "format",
		Shorthand:  "f",
		Default:    string(types.FormatTable),
		Values:     xstrings.ToStringSlice(types.SupportedFormats),
		Usage:      "format",
	}
	ReportFormatFlag = Flag{
		Name:       "report",
		ConfigName: "report",
		Default:    "all",
		Values:     []string{"all", "summary"},
		Usage:      "specify a report format for the output",
	}
	TemplateFlag = Flag{
		Name:       "template",
		ConfigName: "template",
		Shorthand:  "t",
		Default:    "",
		Usage:      "output template",
	}
	DependencyTreeFlag = Flag{
		Name:       "dependency-tree",
		ConfigName: "dependency-tree",
		Default:    false,
		Usage:      "[EXPERIMENTAL] show dependency origin tree of vulnerable packages",
	}
	IgnoreFileFlag = Flag{
		Name:       "ignorefile",
		ConfigName: "ignorefile",
		Default:    result.DefaultIgnoreFile,
		Usage:      "specify .trivyignore file",
	}
	IgnorePolicyFlag = Flag{
		Name:       "ignore-policy",
		ConfigName: "ignore-policy",
		Default:    "",
		Usage:      "specify the Rego file path to evaluate each vulnerability",
	}
	ExitCodeFlag = Flag{
		Name:       "exit-code",
		ConfigName: "exit-code",
		Default:    0,
		Usage:      "specify exit code when any security issues are found",
	}
	ExitOnEOLFlag = Flag{
		Name:       "exit-on-eol",
		ConfigName: "exit-on-eol",
		Default:    0,
		Usage:      "exit with the specified code when the OS reaches end of service/life",
	}
	OutputFlag = Flag{
		Name:       "output",
		ConfigName: "output",
		Shorthand:  "o",
		Default:    "",
		Usage:      "output file name",
	}
	SeverityFlag = Flag{
		Name:       "severity",
		ConfigName: "severity",
		Shorthand:  "s",
		Default:    dbTypes.SeverityNames,
		Values:     dbTypes.SeverityNames,
		Usage:      "severities of security issues to be displayed",
	}
	ComplianceFlag = Flag{
		Name:       "compliance",
		ConfigName: "scan.compliance",
		Default:    "",
		Usage:      "compliance report to generate",
	}
	ListAllPkgsFlag = Flag{
		Name:       "list-all-pkgs",
		ConfigName: "list-all-pkgs",
		Default:    false,
		Usage:      "'--list-all-pkgs' option has been removed. Use '--scanners pkg' to show all packages found.",
		Deprecated: true,
	}
)

// ReportFlagGroup composes common printer flag structs
// used for commands requiring reporting logic.
type ReportFlagGroup struct {
	Format         *Flag
	ReportFormat   *Flag
	Template       *Flag
	DependencyTree *Flag
	IgnoreFile     *Flag
	IgnorePolicy   *Flag
	ExitCode       *Flag
	ExitOnEOL      *Flag
	Output         *Flag
	Severity       *Flag
	Compliance     *Flag
}

type ReportOptions struct {
	Format         types.Format
	ReportFormat   string
	Template       string
	DependencyTree bool
	IgnoreFile     string
	ExitCode       int
	ExitOnEOL      int
	IgnorePolicy   string
	Output         string
	Severities     []dbTypes.Severity
	Compliance     spec.ComplianceSpec
}

func NewReportFlagGroup() *ReportFlagGroup {
	return &ReportFlagGroup{
		Format:         &FormatFlag,
		ReportFormat:   &ReportFormatFlag,
		Template:       &TemplateFlag,
		DependencyTree: &DependencyTreeFlag,
		IgnoreFile:     &IgnoreFileFlag,
		IgnorePolicy:   &IgnorePolicyFlag,
		ExitCode:       &ExitCodeFlag,
		ExitOnEOL:      &ExitOnEOLFlag,
		Output:         &OutputFlag,
		Severity:       &SeverityFlag,
		Compliance:     &ComplianceFlag,
	}
}

func (f *ReportFlagGroup) Name() string {
	return "Report"
}

func (f *ReportFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.Format,
		f.ReportFormat,
		f.Template,
		f.DependencyTree,
		f.IgnoreFile,
		f.IgnorePolicy,
		f.ExitCode,
		f.ExitOnEOL,
		f.Output,
		f.Severity,
		f.Compliance,
	}
}

func (f *ReportFlagGroup) ToOptions() (ReportOptions, error) {
	format := getUnderlyingString[types.Format](f.Format)
	template := getString(f.Template)
	dependencyTree := getBool(f.DependencyTree)

	// `--list-all-pkgs` flag has been removed. Warn about this
	if getBool(&ListAllPkgsFlag) {
		log.Logger.Warn(ListAllPkgsFlag.Usage)
	}

	if template != "" {
		if format == "" {
			log.Logger.Warn("'--template' is ignored because '--format template' is not specified. Use '--template' option with '--format template' option.")
		} else if format != "template" {
			log.Logger.Warnf("'--template' is ignored because '--format %s' is specified. Use '--template' option with '--format template' option.", format)
		}
	} else {
		if format == types.FormatTemplate {
			log.Logger.Warn("'--format template' is ignored because '--template' is not specified. Specify '--template' option when you use '--format template'.")
		}
	}

	// "--dependency-tree" option is available only with "--format table".
	if dependencyTree {
		log.Logger.Infof(`"--dependency-tree" only shows the dependents of vulnerable packages. ` +
			`Note that it is the reverse of the usual dependency tree, which shows the packages that depend on the vulnerable package. ` +
			`It supports limited package managers. Please see the document for the detail.`)
		if format != types.FormatTable {
			log.Logger.Warn(`"--dependency-tree" can be used only with "--format table".`)
		}
	}

	cs, err := loadComplianceTypes(getString(f.Compliance))
	if err != nil {
		return ReportOptions{}, xerrors.Errorf("unable to load compliance spec: %w", err)
	}

	return ReportOptions{
		Format:         format,
		ReportFormat:   getString(f.ReportFormat),
		Template:       template,
		DependencyTree: dependencyTree,
		IgnoreFile:     getString(f.IgnoreFile),
		ExitCode:       getInt(f.ExitCode),
		ExitOnEOL:      getInt(f.ExitOnEOL),
		IgnorePolicy:   getString(f.IgnorePolicy),
		Output:         getString(f.Output),
		Severities:     toSeverity(getStringSlice(f.Severity)),
		Compliance:     cs,
	}, nil
}

func loadComplianceTypes(compliance string) (spec.ComplianceSpec, error) {
	if len(compliance) > 0 && !slices.Contains(types.SupportedCompliances, compliance) && !strings.HasPrefix(compliance, "@") {
		return spec.ComplianceSpec{}, xerrors.Errorf("unknown compliance : %v", compliance)
	}

	cs, err := spec.GetComplianceSpec(compliance)
	if err != nil {
		return spec.ComplianceSpec{}, xerrors.Errorf("spec loading from file system error: %w", err)
	}

	return cs, nil
}

func toSeverity(severity []string) []dbTypes.Severity {
	if len(severity) == 0 {
		return nil
	}
	severities := lo.Map(severity, func(s string, _ int) dbTypes.Severity {
		// Note that there is no need to check the error here
		// since the severity value is already validated in the flag parser.
		sev, _ := dbTypes.NewSeverity(s)
		return sev
	})
	log.Logger.Debugf("Severities: %q", severities)
	return severities
}
