package flag

import (
	"io"
	"os"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
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
		Value:      report.FormatTable,
		Usage:      "format (" + strings.Join(report.SupportedFormats, ", ") + ")",
	}
	ReportFormatFlag = Flag{
		Name:       "report",
		ConfigName: "report",
		Value:      "all",
		Usage:      "specify a report format for the output. (all,summary)",
	}
	TemplateFlag = Flag{
		Name:       "template",
		ConfigName: "template",
		Shorthand:  "t",
		Value:      "",
		Usage:      "output template",
	}
	DependencyTreeFlag = Flag{
		Name:       "dependency-tree",
		ConfigName: "dependency-tree",
		Value:      false,
		Usage:      "[EXPERIMENTAL] show dependency origin tree of vulnerable packages",
	}
	ListAllPkgsFlag = Flag{
		Name:       "list-all-pkgs",
		ConfigName: "list-all-pkgs",
		Value:      false,
		Usage:      "enabling the option will output all packages regardless of vulnerability",
	}
	IgnoreFileFlag = Flag{
		Name:       "ignorefile",
		ConfigName: "ignorefile",
		Value:      result.DefaultIgnoreFile,
		Usage:      "specify .trivyignore file",
	}
	IgnorePolicyFlag = Flag{
		Name:       "ignore-policy",
		ConfigName: "ignore-policy",
		Value:      "",
		Usage:      "specify the Rego file path to evaluate each vulnerability",
	}
	ExitCodeFlag = Flag{
		Name:       "exit-code",
		ConfigName: "exit-code",
		Value:      0,
		Usage:      "specify exit code when any security issues are found",
	}
	OutputFlag = Flag{
		Name:       "output",
		ConfigName: "output",
		Shorthand:  "o",
		Value:      "",
		Usage:      "output file name",
	}
	SeverityFlag = Flag{
		Name:       "severity",
		ConfigName: "severity",
		Shorthand:  "s",
		Value:      strings.Join(dbTypes.SeverityNames, ","),
		Usage:      "severities of security issues to be displayed (comma separated)",
	}
	ComplianceFlag = Flag{
		Name:       "compliance",
		ConfigName: "scan.compliance",
		Value:      "",
		Usage:      "compliance report to generate",
	}
)

// ReportFlagGroup composes common printer flag structs
// used for commands requiring reporting logic.
type ReportFlagGroup struct {
	Format         *Flag
	ReportFormat   *Flag
	Template       *Flag
	DependencyTree *Flag
	ListAllPkgs    *Flag
	IgnoreFile     *Flag
	IgnorePolicy   *Flag
	ExitCode       *Flag
	Output         *Flag
	Severity       *Flag
	Compliance     *Flag
}

type ReportOptions struct {
	Format         string
	ReportFormat   string
	Template       string
	DependencyTree bool
	ListAllPkgs    bool
	IgnoreFile     string
	ExitCode       int
	IgnorePolicy   string
	Output         io.Writer
	Severities     []dbTypes.Severity
	Compliance     string
}

func NewReportFlagGroup() *ReportFlagGroup {
	return &ReportFlagGroup{
		Format:         &FormatFlag,
		ReportFormat:   &ReportFormatFlag,
		Template:       &TemplateFlag,
		DependencyTree: &DependencyTreeFlag,
		ListAllPkgs:    &ListAllPkgsFlag,
		IgnoreFile:     &IgnoreFileFlag,
		IgnorePolicy:   &IgnorePolicyFlag,
		ExitCode:       &ExitCodeFlag,
		Output:         &OutputFlag,
		Severity:       &SeverityFlag,
		Compliance:     &ComplianceFlag,
	}
}

func (f *ReportFlagGroup) Name() string {
	return "Report"
}

func (f *ReportFlagGroup) Flags() []*Flag {
	return []*Flag{f.Format, f.ReportFormat, f.Template, f.DependencyTree, f.ListAllPkgs, f.IgnoreFile,
		f.IgnorePolicy, f.ExitCode, f.Output, f.Severity, f.Compliance}
}

func (f *ReportFlagGroup) ToOptions(out io.Writer) (ReportOptions, error) {
	format := getString(f.Format)
	template := getString(f.Template)
	dependencyTree := getBool(f.DependencyTree)
	listAllPkgs := getBool(f.ListAllPkgs)
	output := getString(f.Output)

	if format != "" && !slices.Contains(report.SupportedFormats, format) {
		return ReportOptions{}, xerrors.Errorf("unknown format: %v", format)
	}

	if template != "" {
		if format == "" {
			log.Logger.Warn("'--template' is ignored because '--format template' is not specified. Use '--template' option with '--format template' option.")
		} else if format != "template" {
			log.Logger.Warnf("'--template' is ignored because '--format %s' is specified. Use '--template' option with '--format template' option.", format)
		}
	} else {
		if format == report.FormatTemplate {
			log.Logger.Warn("'--format template' is ignored because '--template' is not specified. Specify '--template' option when you use '--format template'.")
		}
	}

	// "--list-all-pkgs" option is unavailable with "--format table".
	// If user specifies "--list-all-pkgs" with "--format table", we should warn it.
	if listAllPkgs && format == report.FormatTable {
		log.Logger.Warn(`"--list-all-pkgs" cannot be used with "--format table". Try "--format json" or other formats.`)
	}

	// "--dependency-tree" option is available only with "--format table".
	if dependencyTree {
		log.Logger.Infof(`"--dependency-tree" only shows the dependents of vulnerable packages. ` +
			`Note that it is the reverse of the usual dependency tree, which shows the packages that depend on the vulnerable package. ` +
			`It supports "package-lock.json", "Cargo.lock" and OS packages. Please see the document for the detail.`)
		if format != report.FormatTable {
			log.Logger.Warn(`"--dependency-tree" can be used only with "--format table".`)
		}
	}

	// Enable '--list-all-pkgs' if needed
	if f.forceListAllPkgs(format, listAllPkgs, dependencyTree) {
		listAllPkgs = true
	}

	if output != "" {
		var err error
		if out, err = os.Create(output); err != nil {
			return ReportOptions{}, xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

	complianceTypes, err := parseComplianceTypes(getString(f.Compliance))
	if err != nil {
		return ReportOptions{}, xerrors.Errorf("unable to parse compliance types: %w", err)
	}

	return ReportOptions{
		Format:         format,
		ReportFormat:   getString(f.ReportFormat),
		Template:       template,
		DependencyTree: dependencyTree,
		ListAllPkgs:    listAllPkgs,
		IgnoreFile:     getString(f.IgnoreFile),
		ExitCode:       getInt(f.ExitCode),
		IgnorePolicy:   getString(f.IgnorePolicy),
		Output:         out,
		Severities:     splitSeverity(getStringSlice(f.Severity)),
		Compliance:     complianceTypes,
	}, nil
}

func parseComplianceTypes(compliance string) (string, error) {
	if len(compliance) > 0 && !slices.Contains(types.Compliances, compliance) && !strings.HasPrefix(compliance, "@") {
		return "", xerrors.Errorf("unknown compliance : %v", compliance)
	}
	return compliance, nil
}

func (f *ReportFlagGroup) forceListAllPkgs(format string, listAllPkgs, dependencyTree bool) bool {
	if slices.Contains(report.SupportedSBOMFormats, format) && !listAllPkgs {
		log.Logger.Debugf("%q automatically enables '--list-all-pkgs'.", report.SupportedSBOMFormats)
		return true
	}
	// We need this flag to insert dependency locations into Sarif('Package' struct contains 'Locations')
	if format == report.FormatSarif && !listAllPkgs {
		log.Logger.Debugf("Sarif format automatically enables '--list-all-pkgs' to get locations")
		return true
	}
	if dependencyTree && !listAllPkgs {
		log.Logger.Debugf("'--dependency-tree' enables '--list-all-pkgs'.")
		return true
	}
	return false
}

func splitSeverity(severity []string) []dbTypes.Severity {
	switch {
	case len(severity) == 0:
		return nil
	case len(severity) == 1 && strings.Contains(severity[0], ","): // get severities from flag
		severity = strings.Split(severity[0], ",")
	}

	var severities []dbTypes.Severity
	for _, s := range severity {
		sev, err := dbTypes.NewSeverity(strings.ToUpper(s))
		if err != nil {
			log.Logger.Warnf("unknown severity option: %s", err)
			continue
		}
		severities = append(severities, sev)
	}
	log.Logger.Debugf("Severities: %q", severities)
	return severities
}
