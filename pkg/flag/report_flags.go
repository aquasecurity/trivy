package flag

import (
	"io"
	"os"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
)

// e.g. config yaml
// report:
//   format: table
//   dependency-tree: true
//   exit-code: 1
//   severity: HIGH,CRITICAL
var (
	FormatFlag = Flag{
		Name:       "format",
		ConfigName: "report.format",
		Shorthand:  "f",
		Value:      report.FormatTable,
		Usage:      "format (table, json, sarif, template, cyclonedx, spdx, spdx-json, github)",
	}
	TemplateFlag = Flag{
		Name:       "template",
		ConfigName: "report.template",
		Shorthand:  "t",
		Value:      "",
		Usage:      "output template",
	}
	DependencyTreeFlag = Flag{
		Name:       "dependency-tree",
		ConfigName: "report.dependency-tree",
		Value:      false,
		Usage:      "show dependency origin tree (EXPERIMENTAL)",
	}
	ListAllPkgsFlag = Flag{
		Name:       "list-all-pkgs",
		ConfigName: "report.list-all-pkgs",
		Value:      false,
		Usage:      "enabling the option will output all packages regardless of vulnerability",
	}
	IgnoreUnfixedFlag = Flag{
		Name:       "ignore-unfixed",
		ConfigName: "report.ignore-unfixed",
		Value:      false,
		Usage:      "display only fixed vulnerabilities",
	}
	IgnoreFileFlag = Flag{
		Name:       "ignorefile",
		ConfigName: "report.ignorefile",
		Value:      result.DefaultIgnoreFile,
		Usage:      "specify .trivyignore file",
	}
	IgnorePolicyFlag = Flag{
		Name:       "ignore-policy",
		ConfigName: "report.ignore-policy",
		Value:      "",
		Usage:      "specify the Rego file path to evaluate each vulnerability",
	}
	ExitCodeFlag = Flag{
		Name:       "exit-code",
		ConfigName: "report.exit-code",
		Value:      0,
		Usage:      "specify exit code when any security issues are found",
	}
	OutputFlag = Flag{
		Name:       "output",
		ConfigName: "report.output",
		Shorthand:  "o",
		Value:      "",
		Usage:      "output file name",
	}
	SeverityFlag = Flag{
		Name:       "severity",
		ConfigName: "report.severity",
		Shorthand:  "s",
		Value:      strings.Join(dbTypes.SeverityNames, ","),
		Usage:      "severities of security issues to be displayed (comma separated)",
	}
)

// ReportFlags composes common printer flag structs
// used for commands requiring reporting logic.
type ReportFlags struct {
	Format         *Flag
	Template       *Flag
	DependencyTree *Flag
	ListAllPkgs    *Flag
	IgnoreUnfixed  *Flag
	IgnoreFile     *Flag
	IgnorePolicy   *Flag
	ExitCode       *Flag
	Output         *Flag
	Severity       *Flag
}

type ReportOptions struct {
	Format         string
	Template       string
	DependencyTree bool
	ListAllPkgs    bool
	IgnoreUnfixed  bool
	IgnoreFile     string
	ExitCode       int
	IgnorePolicy   string
	Output         io.Writer
	Severities     []dbTypes.Severity
}

func NewReportFlags() *ReportFlags {
	return &ReportFlags{
		Format:         lo.ToPtr(FormatFlag),
		Template:       lo.ToPtr(TemplateFlag),
		DependencyTree: lo.ToPtr(DependencyTreeFlag),
		ListAllPkgs:    lo.ToPtr(ListAllPkgsFlag),
		IgnoreUnfixed:  lo.ToPtr(IgnoreUnfixedFlag),
		IgnoreFile:     lo.ToPtr(IgnoreFileFlag),
		IgnorePolicy:   lo.ToPtr(IgnorePolicyFlag),
		ExitCode:       lo.ToPtr(ExitCodeFlag),
		Output:         lo.ToPtr(OutputFlag),
		Severity:       lo.ToPtr(SeverityFlag),
	}
}

func (f *ReportFlags) flags() []*Flag {
	return []*Flag{f.Format, f.Template, f.DependencyTree, f.ListAllPkgs, f.IgnoreUnfixed, f.IgnoreFile, f.IgnorePolicy,
		f.ExitCode, f.Output, f.Severity}
}

func (f *ReportFlags) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *ReportFlags) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *ReportFlags) ToOptions(out io.Writer) (ReportOptions, error) {
	format := get[string](f.Format)
	template := get[string](f.Template)
	dependencyTree := get[bool](f.DependencyTree)
	listAllPkgs := get[bool](f.ListAllPkgs)
	output := get[string](f.Output)

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
	if dependencyTree && format != report.FormatTable {
		log.Logger.Warn(`"--dependency-tree" can be used only with "--format table".`)
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

	return ReportOptions{
		Format:         format,
		Template:       template,
		DependencyTree: dependencyTree,
		ListAllPkgs:    listAllPkgs,
		IgnoreUnfixed:  get[bool](f.IgnoreUnfixed),
		IgnoreFile:     get[string](f.IgnoreFile),
		ExitCode:       get[int](f.ExitCode),
		IgnorePolicy:   get[string](f.IgnorePolicy),
		Output:         out,
		Severities:     splitSeverity(get[string](f.Severity)),
	}, nil
}

func (f *ReportFlags) forceListAllPkgs(format string, listAllPkgs, dependencyTree bool) bool {
	if slices.Contains(report.SupportedSBOMFormats, format) && !listAllPkgs {
		log.Logger.Debugf("%q automatically enables '--list-all-pkgs'.", report.SupportedSBOMFormats)
		return true
	}
	if dependencyTree && !listAllPkgs {
		log.Logger.Debugf("'--dependency-tree' enables '--list-all-pkgs'.")
		return true
	}
	return false
}

func splitSeverity(severity string) []dbTypes.Severity {
	if severity == "" {
		return nil
	}

	var severities []dbTypes.Severity
	for _, s := range strings.Split(severity, ",") {
		sev, err := dbTypes.NewSeverity(s)
		if err != nil {
			log.Logger.Warnf("unknown severity option: %s", err)
			continue
		}
		severities = append(severities, sev)
	}
	log.Logger.Debugf("Severities: %q", severities)
	return severities
}
