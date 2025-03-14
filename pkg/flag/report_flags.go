package flag

import (
	"slices"
	"strings"

	"github.com/mattn/go-shellwords"
	"github.com/samber/lo"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

// e.g. config yaml:
//
//	format: table
//	dependency-tree: true
//	severity: HIGH,CRITICAL
var (
	FormatFlag = Flag[string]{
		Name:       "format",
		ConfigName: "format",
		Shorthand:  "f",
		Default:    string(types.FormatTable),
		Values:     xstrings.ToStringSlice(types.SupportedFormats),
		Usage:      "format",
	}
	ReportFormatFlag = Flag[string]{
		Name:       "report",
		ConfigName: "report",
		Default:    "all",
		Values: []string{
			"all",
			"summary",
		},
		Usage: "specify a report format for the output",
	}
	TemplateFlag = Flag[string]{
		Name:       "template",
		ConfigName: "template",
		Shorthand:  "t",
		Usage:      "output template",
	}
	DependencyTreeFlag = Flag[bool]{
		Name:       "dependency-tree",
		ConfigName: "dependency-tree",
		Usage:      "[EXPERIMENTAL] show dependency origin tree of vulnerable packages",
	}
	ListAllPkgsFlag = Flag[bool]{
		Name:       "list-all-pkgs",
		ConfigName: "list-all-pkgs",
		Usage:      "output all packages in the JSON report regardless of vulnerability",
	}
	IgnoreFileFlag = Flag[string]{
		Name:       "ignorefile",
		ConfigName: "ignorefile",
		Default:    result.DefaultIgnoreFile,
		Usage:      "specify .trivyignore file",
	}
	IgnorePolicyFlag = Flag[string]{
		Name:       "ignore-policy",
		ConfigName: "ignore-policy",
		Usage:      "specify the Rego file path to evaluate each vulnerability",
	}
	ExitCodeFlag = Flag[int]{
		Name:       "exit-code",
		ConfigName: "exit-code",
		Usage:      "specify exit code when any security issues are found",
	}
	ExitOnEOLFlag = Flag[int]{
		Name:       "exit-on-eol",
		ConfigName: "exit-on-eol",
		Usage:      "exit with the specified code when the OS reaches end of service/life",
	}
	OutputFlag = Flag[string]{
		Name:       "output",
		ConfigName: "output",
		Shorthand:  "o",
		Usage:      "output file name",
	}
	OutputPluginArgFlag = Flag[string]{
		Name:       "output-plugin-arg",
		ConfigName: "output-plugin-arg",
		Usage:      "[EXPERIMENTAL] output plugin arguments",
	}
	SeverityFlag = Flag[[]string]{
		Name:       "severity",
		ConfigName: "severity",
		Shorthand:  "s",
		Default:    dbTypes.SeverityNames,
		Values:     dbTypes.SeverityNames,
		Usage:      "severities of security issues to be displayed",
	}
	ComplianceFlag = Flag[string]{
		Name:       "compliance",
		ConfigName: "scan.compliance",
		Usage:      "compliance report to generate",
	}
	ShowSuppressedFlag = Flag[bool]{
		Name:       "show-suppressed",
		ConfigName: "scan.show-suppressed",
		Usage:      "[EXPERIMENTAL] show suppressed vulnerabilities",
	}
	TableModeFlag = Flag[[]string]{
		Name:       "table-mode",
		ConfigName: "table-mode",
		Default:    xstrings.ToStringSlice(types.SupportedTableModes),
		Values:     xstrings.ToStringSlice(types.SupportedTableModes),
		Usage:      "[EXPERIMENTAL] tables that will be displayed in 'table' format",
	}
)

// ReportFlagGroup composes common printer flag structs
// used for commands requiring reporting logic.
type ReportFlagGroup struct {
	Format          *Flag[string]
	ReportFormat    *Flag[string]
	Template        *Flag[string]
	DependencyTree  *Flag[bool]
	ListAllPkgs     *Flag[bool]
	IgnoreFile      *Flag[string]
	IgnorePolicy    *Flag[string]
	ExitCode        *Flag[int]
	ExitOnEOL       *Flag[int]
	Output          *Flag[string]
	OutputPluginArg *Flag[string]
	Severity        *Flag[[]string]
	Compliance      *Flag[string]
	ShowSuppressed  *Flag[bool]
	TableMode       *Flag[[]string]
}

type ReportOptions struct {
	Format           types.Format
	ReportFormat     string
	Template         string
	DependencyTree   bool
	ListAllPkgs      bool
	IgnoreFile       string
	ExitCode         int
	ExitOnEOL        int
	IgnorePolicy     string
	Output           string
	OutputPluginArgs []string
	Severities       []dbTypes.Severity
	Compliance       spec.ComplianceSpec
	ShowSuppressed   bool
	TableModes       []types.TableMode
}

func NewReportFlagGroup() *ReportFlagGroup {
	return &ReportFlagGroup{
		Format:          FormatFlag.Clone(),
		ReportFormat:    ReportFormatFlag.Clone(),
		Template:        TemplateFlag.Clone(),
		DependencyTree:  DependencyTreeFlag.Clone(),
		ListAllPkgs:     ListAllPkgsFlag.Clone(),
		IgnoreFile:      IgnoreFileFlag.Clone(),
		IgnorePolicy:    IgnorePolicyFlag.Clone(),
		ExitCode:        ExitCodeFlag.Clone(),
		ExitOnEOL:       ExitOnEOLFlag.Clone(),
		Output:          OutputFlag.Clone(),
		OutputPluginArg: OutputPluginArgFlag.Clone(),
		Severity:        SeverityFlag.Clone(),
		Compliance:      ComplianceFlag.Clone(),
		ShowSuppressed:  ShowSuppressedFlag.Clone(),
		TableMode:       TableModeFlag.Clone(),
	}
}

func (f *ReportFlagGroup) Name() string {
	return "Report"
}

func (f *ReportFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Format,
		f.ReportFormat,
		f.Template,
		f.DependencyTree,
		f.ListAllPkgs,
		f.IgnoreFile,
		f.IgnorePolicy,
		f.ExitCode,
		f.ExitOnEOL,
		f.Output,
		f.OutputPluginArg,
		f.Severity,
		f.Compliance,
		f.ShowSuppressed,
		f.TableMode,
	}
}

func (f *ReportFlagGroup) ToOptions() (ReportOptions, error) {
	if err := parseFlags(f); err != nil {
		return ReportOptions{}, err
	}

	format := types.Format(f.Format.Value())
	template := f.Template.Value()
	dependencyTree := f.DependencyTree.Value()
	listAllPkgs := f.ListAllPkgs.Value()
	tableModes := f.TableMode.Value()

	if template != "" {
		if format == "" {
			log.Warn("'--template' is ignored because '--format template' is not specified. Use '--template' option with '--format template' option.")
		} else if format != "template" {
			log.Warnf("'--template' is ignored because '--format %s' is specified. Use '--template' option with '--format template' option.", format)
		}
	} else {
		if format == types.FormatTemplate {
			log.Warn("'--format template' is ignored because '--template' is not specified. Specify '--template' option when you use '--format template'.")
		}
	}

	// "--list-all-pkgs" option is unavailable with other than "--format json".
	// If user specifies "--list-all-pkgs" with "--format table" or other formats, we should warn it.
	if listAllPkgs && format != types.FormatJSON {
		log.Warn(`"--list-all-pkgs" is only valid for the JSON format, for other formats a list of packages is automatically included.`)
	}

	// "--dependency-tree" option is available only with "--format table".
	if dependencyTree {
		log.Info(`"--dependency-tree" only shows the dependents of vulnerable packages. ` +
			`Note that it is the reverse of the usual dependency tree, which shows the packages that depend on the vulnerable package. ` +
			`It supports limited package managers. Please see the document for the detail.`)
		if format != types.FormatTable {
			log.Warn(`"--dependency-tree" can be used only with "--format table".`)
		}
	}

	// "--table-mode" option is available only with "--format table".
	if viper.IsSet(TableModeFlag.ConfigName) && format != types.FormatTable {
		return ReportOptions{}, xerrors.New(`"--table-mode" can be used only with "--format table".`)
	}

	cs, err := loadComplianceTypes(f.Compliance.Value())
	if err != nil {
		return ReportOptions{}, xerrors.Errorf("unable to load compliance spec: %w", err)
	}

	var outputPluginArgs []string
	if arg := f.OutputPluginArg.Value(); arg != "" {
		outputPluginArgs, err = shellwords.Parse(arg)
		if err != nil {
			return ReportOptions{}, xerrors.Errorf("unable to parse output plugin argument: %w", err)
		}
	}

	if viper.IsSet(f.IgnoreFile.ConfigName) && !fsutils.FileExists(f.IgnoreFile.Value()) {
		return ReportOptions{}, xerrors.Errorf("ignore file not found: %s", f.IgnoreFile.Value())
	}

	return ReportOptions{
		Format:           format,
		ReportFormat:     f.ReportFormat.Value(),
		Template:         template,
		DependencyTree:   dependencyTree,
		ListAllPkgs:      listAllPkgs,
		IgnoreFile:       f.IgnoreFile.Value(),
		ExitCode:         f.ExitCode.Value(),
		ExitOnEOL:        f.ExitOnEOL.Value(),
		IgnorePolicy:     f.IgnorePolicy.Value(),
		Output:           f.Output.Value(),
		OutputPluginArgs: outputPluginArgs,
		Severities:       toSeverity(f.Severity.Value()),
		Compliance:       cs,
		ShowSuppressed:   f.ShowSuppressed.Value(),
		TableModes:       xstrings.ToTSlice[types.TableMode](tableModes),
	}, nil
}

func loadComplianceTypes(compliance string) (spec.ComplianceSpec, error) {
	if compliance != "" && !slices.Contains(types.SupportedCompliances, compliance) && !strings.HasPrefix(compliance, "@") {
		return spec.ComplianceSpec{}, xerrors.Errorf("unknown compliance : %v", compliance)
	}

	cs, err := spec.GetComplianceSpec(compliance, cache.DefaultDir())
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
	log.Debug("Parsed severities", log.Any("severities", severities))
	return severities
}
