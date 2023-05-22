package flag

import (
	"fmt"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/log"
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
		Value:      string(types.FormatTable),
		Usage: "format (" + strings.Join(
			lo.Map(types.SupportedFormats, func(item types.Format, _ int) string {
				return string(item)
			}),
			", ") + ")",
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
	ExitOnEOLFlag = Flag{
		Name:       "exit-on-eol",
		ConfigName: "exit-on-eol",
		Value:      0,
		Usage:      "exit with the specified code when the OS reaches end of service/life",
	}
	OutputFlag = Flag{
		Name:       "output",
		ConfigName: "output",
		Shorthand:  "o",
		Value:      "stdout",
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
	OutputsFlag = Flag{
		Name:       "experimental-output",
		ConfigName: "experimental-output",
		Value:      "",
		Usage:      "[EXPERIMENTAL] a list of outputs",
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
	ExitOnEOL      *Flag
	Output         *Flag
	Severity       *Flag
	Compliance     *Flag
	Outputs        *Flag
}

type ReportOptions struct {
	ReportFormat   string
	DependencyTree bool
	ListAllPkgs    bool
	IgnoreFile     string
	ExitCode       int
	ExitOnEOL      int
	IgnorePolicy   string
	Severities     []dbTypes.Severity
	Compliance     spec.ComplianceSpec
	Outputs        types.Outputs
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
		ExitOnEOL:      &ExitOnEOLFlag,
		Output:         &OutputFlag,
		Severity:       &SeverityFlag,
		Compliance:     &ComplianceFlag,
		Outputs:        &OutputsFlag,
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
		f.ListAllPkgs,
		f.IgnoreFile,
		f.IgnorePolicy,
		f.ExitCode,
		f.ExitOnEOL,
		f.Output,
		f.Severity,
		f.Compliance,
		f.Outputs,
	}
}

func (f *ReportFlagGroup) ToOptions() (ReportOptions, error) {
	dependencyTree := getBool(f.DependencyTree)
	listAllPkgs := getBool(f.ListAllPkgs)

	fmt.Printf("%#v\n", getValue(f.Outputs))
	outputs, err := parseOutputs(getStringSlice(f.Outputs))
	if err != nil {
		return ReportOptions{}, xerrors.Errorf("output error: %w", err)
	} else if len(outputs) == 0 {
		outputs = append(outputs, types.Output{
			Format:   types.Format(getString(f.Format)),
			Dest:     getString(f.Output),
			Template: getString(f.Template),
		})
	}

	for _, output := range outputs {
		if output.Format != "" && !slices.Contains(types.SupportedFormats, output.Format) {
			return ReportOptions{}, xerrors.Errorf("unknown format: %s", output.Format)
		}

		if output.Template != "" {
			if output.Format == "" {
				log.Logger.Warn("'--template' is ignored because '--format template' is not specified. Use '--template' option with '--format template' option.")
			} else if output.Format != "template" {
				log.Logger.Warnf("'--template' is ignored because '--format %s' is specified. Use '--template' option with '--format template' option.", output.Format)
			}
		} else {
			if output.Format == types.FormatTemplate {
				log.Logger.Warn("'--format template' is ignored because '--template' is not specified. Specify '--template' option when you use '--format template'.")
			}
		}
	}

	// "--list-all-pkgs" option is unavailable with "--format table".
	// If user specifies "--list-all-pkgs" with "--format table", we should warn it.
	if listAllPkgs && outputs.Only(types.FormatTable) {
		log.Logger.Warn(`"--list-all-pkgs" cannot be used with "--format table". Try "--format json" or other formats.`)
	}

	// "--dependency-tree" option is available only with "--format table".
	if dependencyTree {
		log.Logger.Infof(`"--dependency-tree" only shows the dependents of vulnerable packages. ` +
			`Note that it is the reverse of the usual dependency tree, which shows the packages that depend on the vulnerable package. ` +
			`It supports limited package managers. Please see the document for the detail.`)
		if !outputs.Contains(types.FormatTable) {
			log.Logger.Warn(`"--dependency-tree" can be used only with "--format table".`)
		}
	}

	// Enable '--list-all-pkgs' if needed
	if f.forceListAllPkgs(outputs, listAllPkgs, dependencyTree) {
		listAllPkgs = true
	}

	cs, err := loadComplianceTypes(getString(f.Compliance))
	if err != nil {
		return ReportOptions{}, xerrors.Errorf("unable to load compliance spec: %w", err)
	}

	return ReportOptions{
		ReportFormat:   getString(f.ReportFormat),
		DependencyTree: dependencyTree,
		ListAllPkgs:    listAllPkgs,
		IgnoreFile:     getString(f.IgnoreFile),
		ExitCode:       getInt(f.ExitCode),
		ExitOnEOL:      getInt(f.ExitOnEOL),
		IgnorePolicy:   getString(f.IgnorePolicy),
		Severities:     splitSeverity(getStringSlice(f.Severity)),
		Compliance:     cs,
		Outputs:        outputs,
	}, nil
}

func parseOutputs(ss []string) (types.Outputs, error) {
	var outputs types.Outputs

	fmt.Println(ss)
	for _, out := range ss {
		var output types.Output
		pairs := strings.Split(out, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				return nil, xerrors.Errorf("invalid output format: %s", pair)
			}

			key, value := kv[0], kv[1]

			switch key {
			case "format":
				output.Format = types.Format(value)
			case "template":
				output.Template = value
			case "dest":
				output.Dest = value
			default:
				log.Logger.Warnf("Invalid output key: %s", key)
			}
		}
		if output.Format == "" {
			return nil, xerrors.Errorf("'format' must be specified: %s", out)
		}
		outputs = append(outputs, output)
	}

	return outputs, nil
}

func loadComplianceTypes(compliance string) (spec.ComplianceSpec, error) {
	if len(compliance) > 0 && !slices.Contains(types.Compliances, compliance) && !strings.HasPrefix(compliance, "@") {
		return spec.ComplianceSpec{}, xerrors.Errorf("unknown compliance : %v", compliance)
	}

	cs, err := spec.GetComplianceSpec(compliance)
	if err != nil {
		return spec.ComplianceSpec{}, xerrors.Errorf("spec loading from file system error: %w", err)
	}

	return cs, nil
}

func (f *ReportFlagGroup) forceListAllPkgs(outputs types.Outputs, listAllPkgs, dependencyTree bool) bool {
	for _, sbomFormat := range types.SupportedSBOMFormats {
		if outputs.Contains(sbomFormat) && !listAllPkgs {
			log.Logger.Debugf("%q automatically enables '--list-all-pkgs'.", types.SupportedSBOMFormats)
			return true
		}
	}
	// We need this flag to insert dependency locations into SARIF('Package' struct contains 'Locations')
	if outputs.Contains(types.FormatSarif) && !listAllPkgs {
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
