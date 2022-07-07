package flag

import (
	"io"
	"os"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
)

const (
	ListAllPkgsFlag   = "list-all-pkgs"
	IgnoreUnfixedFlag = "ignore-unfixed"
	IgnoreFileFlag    = "ignorefile"
	ExitCodeFlag      = "exit-code"
	IgnorePolicyFlag  = "ignore-policy"
	OutputFlag        = "output"
	SeverityFlag      = "severity"
)

// e.g. config yaml
// report:
//   format: table
//   dependency-tree: true
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
)

// ReportFlags composes common printer flag structs
// used for commands requiring reporting logic.
type ReportFlags struct {
	Format         *Flag
	Template       *Flag
	DependencyTree *Flag
	ListAllPkgs    *bool
	IgnoreUnfixed  *bool
	IgnoreFile     *string
	ExitCode       *int
	IgnorePolicy   *string

	Output   *string
	Severity *string
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

	Output     io.Writer
	Severities []dbTypes.Severity
}

func NewReportFlags() *ReportFlags {
	return &ReportFlags{
		Format:         lo.ToPtr(FormatFlag),
		Template:       lo.ToPtr(TemplateFlag),
		DependencyTree: lo.ToPtr(DependencyTreeFlag),
		ListAllPkgs:    lo.ToPtr(false),
		IgnoreUnfixed:  lo.ToPtr(false),
		IgnoreFile:     lo.ToPtr(result.DefaultIgnoreFile),
		ExitCode:       lo.ToPtr(0),
		IgnorePolicy:   lo.ToPtr(""),
		Output:         lo.ToPtr(""),
		Severity:       lo.ToPtr(strings.Join(dbTypes.SeverityNames, ",")),
	}
}

func (f *ReportFlags) AddFlags(cmd *cobra.Command) {
	addFlag(cmd, f.Format)
	addFlag(cmd, f.Template)
	addFlag(cmd, f.DependencyTree)

	if f.ListAllPkgs != nil {
		cmd.Flags().Bool(ListAllPkgsFlag, *f.ListAllPkgs, "enabling the option will output all packages regardless of vulnerability")
	}
	if f.IgnoreUnfixed != nil {
		cmd.Flags().Bool(IgnoreUnfixedFlag, *f.IgnoreUnfixed, "display only fixed vulnerabilities")
	}
	if f.IgnoreFile != nil {
		cmd.Flags().String(IgnoreFileFlag, *f.IgnoreFile, "specify .trivyignore file")
	}
	if f.ExitCode != nil {
		cmd.Flags().Int(ExitCodeFlag, *f.ExitCode, "specify exit code when any security issues are found")
	}
	if f.IgnorePolicy != nil {
		cmd.Flags().String(IgnorePolicyFlag, *f.IgnorePolicy, "specify the Rego file to evaluate each vulnerability")
	}
	if f.Output != nil {
		cmd.Flags().StringP(OutputFlag, "o", *f.Output, "output file name")
	}
	if f.Severity != nil {
		cmd.Flags().StringP(SeverityFlag, "s", *f.Severity, "severities of security issues to be displayed (comma separated)")
	}
}

func (f *ReportFlags) Bind(cmd *cobra.Command) error {
	flags := []*Flag{f.Format, f.Template, f.DependencyTree}
	for _, flag := range flags {
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
	listAllPkgs := viper.GetBool(ListAllPkgsFlag)
	output := viper.GetString(OutputFlag)

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
		IgnoreUnfixed:  viper.GetBool(IgnoreUnfixedFlag),
		IgnoreFile:     viper.GetString(IgnoreFileFlag),
		ExitCode:       viper.GetInt(ExitCodeFlag),
		IgnorePolicy:   viper.GetString(IgnorePolicyFlag),
		Output:         out,
		Severities:     splitSeverity(viper.GetString(SeverityFlag)),
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
