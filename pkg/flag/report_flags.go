package flag

import (
	"strings"

	"github.com/mattn/go-shellwords"
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
		Usage:      "enabling the option will output all packages regardless of vulnerability",
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

	// "--list-all-pkgs" option is unavailable with "--format table".
	// If user specifies "--list-all-pkgs" with "--format table", we should warn it.
	if listAllPkgs && format == types.FormatTable {
		log.Logger.Warn(`"--list-all-pkgs" cannot be used with "--format table". Try "--format json" or other formats.`)
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

	// Enable '--list-all-pkgs' if needed
	if f.forceListAllPkgs(format, listAllPkgs, dependencyTree) {
		listAllPkgs = true
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

func (f *ReportFlagGroup) forceListAllPkgs(format types.Format, listAllPkgs, dependencyTree bool) bool {
	if slices.Contains(types.SupportedSBOMFormats, format) && !listAllPkgs {
		log.Logger.Debugf("%q automatically enables '--list-all-pkgs'.", types.SupportedSBOMFormats)
		return true
	}
	// We need this flag to insert dependency locations into Sarif('Package' struct contains 'Locations')
	if format == types.FormatSarif && !listAllPkgs {
		log.Logger.Debugf("Sarif format automatically enables '--list-all-pkgs' to get locations")
		return true
	}
	if dependencyTree && !listAllPkgs {
		log.Logger.Debugf("'--dependency-tree' enables '--list-all-pkgs'.")
		return true
	}
	return false
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
