package misconf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm"
	cfscanner "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
	cfparser "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	dfscanner "github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/generic"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm"
	k8sscanner "github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	tfprawscanner "github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/snapshot"
	tfpjsonscanner "github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/tfjson"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/mapfs"

	_ "embed"
)

var enablediacTypes = map[detection.FileType]types.ConfigType{
	detection.FileTypeAzureARM:              types.AzureARM,
	detection.FileTypeCloudFormation:        types.CloudFormation,
	detection.FileTypeTerraform:             types.Terraform,
	detection.FileTypeDockerfile:            types.Dockerfile,
	detection.FileTypeKubernetes:            types.Kubernetes,
	detection.FileTypeHelm:                  types.Helm,
	detection.FileTypeTerraformPlanJSON:     types.TerraformPlanJSON,
	detection.FileTypeTerraformPlanSnapshot: types.TerraformPlanSnapshot,
	detection.FileTypeJSON:                  types.JSON,
	detection.FileTypeYAML:                  types.YAML,
}

type DisabledCheck struct {
	ID      string
	Scanner string // For logging
	Reason  string // For logging
}

type ScannerOption struct {
	Trace                    bool
	Namespaces               []string
	PolicyPaths              []string
	DataPaths                []string
	DisableEmbeddedPolicies  bool
	DisableEmbeddedLibraries bool
	IncludeDeprecatedChecks  bool

	HelmValues              []string
	HelmValueFiles          []string
	HelmFileValues          []string
	HelmStringValues        []string
	HelmAPIVersions         []string
	HelmKubeVersion         string
	TerraformTFVars         []string
	CloudFormationParamVars []string
	TfExcludeDownloaded     bool
	K8sVersion              string

	FilePatterns      []string
	ConfigFileSchemas []*ConfigFileSchema

	DisabledChecks []DisabledCheck
	SkipFiles      []string
	SkipDirs       []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

type Scanner struct {
	fileType          detection.FileType
	scanner           scanners.FSScanner
	hasFilePattern    bool
	configFileSchemas []*ConfigFileSchema
}

func NewScanner(t detection.FileType, opt ScannerOption) (*Scanner, error) {
	opts, err := scannerOptions(t, opt)
	if err != nil {
		return nil, err
	}

	var scanner scanners.FSScanner
	switch t {
	case detection.FileTypeAzureARM:
		scanner = arm.New(opts...)
	case detection.FileTypeCloudFormation:
		scanner = cfscanner.New(opts...)
	case detection.FileTypeDockerfile:
		scanner = dfscanner.NewScanner(opts...)
	case detection.FileTypeHelm:
		scanner = helm.New(opts...)
	case detection.FileTypeKubernetes:
		scanner = k8sscanner.NewScanner(opts...)
	case detection.FileTypeTerraform:
		scanner = terraform.New(opts...)
	case detection.FileTypeTerraformPlanJSON:
		scanner = tfpjsonscanner.New(opts...)
	case detection.FileTypeTerraformPlanSnapshot:
		scanner = tfprawscanner.New(opts...)
	case detection.FileTypeYAML:
		scanner = generic.NewYamlScanner(opts...)
	case detection.FileTypeJSON:
		scanner = generic.NewJsonScanner(opts...)
	default:
		return nil, xerrors.Errorf("unknown file type: %s", t)
	}

	return &Scanner{
		fileType:          t,
		scanner:           scanner,
		hasFilePattern:    hasFilePattern(t, opt.FilePatterns),
		configFileSchemas: opt.ConfigFileSchemas,
	}, nil
}

func (s *Scanner) Scan(ctx context.Context, fsys fs.FS) ([]types.Misconfiguration, error) {
	ctx = log.WithContextPrefix(ctx, log.PrefixMisconfiguration)
	newfs, err := s.filterFS(fsys)
	if err != nil {
		return nil, xerrors.Errorf("fs filter error: %w", err)
	} else if newfs == nil {
		// Skip scanning if no relevant files are found
		return nil, nil
	}

	log.DebugContext(ctx, "Scanning files for misconfigurations...", log.String("scanner", s.scanner.Name()))
	results, err := s.scanner.ScanFS(ctx, newfs, ".")
	if err != nil {
		var invalidContentError *cfparser.InvalidContentError
		if errors.As(err, &invalidContentError) {
			log.ErrorContext(ctx, "scan was broken with InvalidContentError", s.scanner.Name(), log.Err(err))
			return nil, nil
		}
		return nil, xerrors.Errorf("scan config error: %w", err)
	}

	configType := enablediacTypes[s.fileType]
	misconfs := ResultsToMisconf(configType, s.scanner.Name(), results)

	// Sort misconfigurations
	for _, misconf := range misconfs {
		sort.Sort(misconf.Successes)
		sort.Sort(misconf.Warnings)
		sort.Sort(misconf.Failures)
	}

	return misconfs, nil
}

func (s *Scanner) filterFS(fsys fs.FS) (fs.FS, error) {
	mfs, ok := fsys.(*mapfs.FS)
	if !ok {
		// Unable to filter this filesystem
		return fsys, nil
	}

	schemas := lo.SliceToMap(s.configFileSchemas, func(schema *ConfigFileSchema) (string, *gojsonschema.Schema) {
		return schema.path, schema.schema
	})

	var foundRelevantFile bool
	filter := func(path string, d fs.DirEntry) (bool, error) {
		file, err := fsys.Open(path)
		if err != nil {
			return false, err
		}
		defer file.Close()

		rs, ok := file.(io.ReadSeeker)
		if !ok {
			return false, xerrors.Errorf("type assertion error: %w", err)
		}

		if len(schemas) > 0 &&
			(s.fileType == detection.FileTypeYAML || s.fileType == detection.FileTypeJSON) &&
			!detection.IsFileMatchesSchemas(schemas, s.fileType, path, rs) {
			return true, nil
		} else if !s.hasFilePattern && !detection.IsType(path, rs, s.fileType) {
			return true, nil
		}

		foundRelevantFile = true
		return false, nil
	}
	newfs, err := mfs.FilterFunc(filter)
	if err != nil {
		return nil, xerrors.Errorf("fs filter error: %w", err)
	}
	if !foundRelevantFile {
		return nil, nil
	}
	return newfs, nil
}

func scannerOptions(t detection.FileType, opt ScannerOption) ([]options.ScannerOption, error) {
	disabledCheckIDs := lo.Map(opt.DisabledChecks, func(check DisabledCheck, _ int) string {
		log.Info("Check disabled", log.Prefix(log.PrefixMisconfiguration), log.String("ID", check.ID),
			log.String("scanner", check.Scanner), log.String("reason", check.Reason))
		return check.ID
	})

	opts := []options.ScannerOption{
		rego.WithEmbeddedPolicies(!opt.DisableEmbeddedPolicies),
		rego.WithEmbeddedLibraries(!opt.DisableEmbeddedLibraries),
		rego.WithIncludeDeprecatedChecks(opt.IncludeDeprecatedChecks),
		rego.WithDisabledCheckIDs(disabledCheckIDs...),
	}

	policyFS, policyPaths, err := CreatePolicyFS(opt.PolicyPaths)
	if err != nil {
		return nil, err
	}
	if policyFS != nil {
		opts = append(opts, rego.WithPolicyFilesystem(policyFS))
	}

	dataFS, dataPaths, err := CreateDataFS(opt.DataPaths, opt.K8sVersion)
	if err != nil {
		return nil, err
	}

	schemas := lo.SliceToMap(opt.ConfigFileSchemas, func(schema *ConfigFileSchema) (string, []byte) {
		return schema.name, schema.source
	})

	opts = append(opts,
		rego.WithDataDirs(dataPaths...),
		rego.WithDataFilesystem(dataFS),
		rego.WithCustomSchemas(schemas),
	)

	if opt.Trace {
		opts = append(opts, rego.WithPerResultTracing(true))
	}

	if len(policyPaths) > 0 {
		opts = append(opts, rego.WithPolicyDirs(policyPaths...))
	}

	if len(opt.DataPaths) > 0 {
		opts = append(opts, rego.WithDataDirs(opt.DataPaths...))
	}

	if len(opt.Namespaces) > 0 {
		opts = append(opts, rego.WithPolicyNamespaces(opt.Namespaces...))
	}

	switch t {
	case detection.FileTypeHelm:
		return addHelmOpts(opts, opt), nil
	case detection.FileTypeTerraform, detection.FileTypeTerraformPlanSnapshot:
		return addTFOpts(opts, opt)
	case detection.FileTypeCloudFormation:
		return addCFOpts(opts, opt)
	default:
		return opts, nil
	}
}

func hasFilePattern(t detection.FileType, filePatterns []string) bool {
	for _, pattern := range filePatterns {
		if strings.HasPrefix(pattern, fmt.Sprintf("%s:", t)) {
			return true
		}
	}
	return false
}

func addTFOpts(opts []options.ScannerOption, scannerOption ScannerOption) ([]options.ScannerOption, error) {
	if len(scannerOption.TerraformTFVars) > 0 {
		configFS, err := createConfigFS(scannerOption.TerraformTFVars)
		if err != nil {
			return nil, xerrors.Errorf("failed to create Terraform config FS: %w", err)
		}
		opts = append(
			opts,
			terraform.ScannerWithTFVarsPaths(scannerOption.TerraformTFVars...),
			terraform.ScannerWithConfigsFileSystem(configFS),
		)
	}

	opts = append(opts,
		terraform.ScannerWithAllDirectories(true),
		terraform.ScannerWithSkipDownloaded(scannerOption.TfExcludeDownloaded),
		terraform.ScannerWithSkipFiles(scannerOption.SkipFiles),
		terraform.ScannerWithSkipDirs(scannerOption.SkipDirs),
	)

	return opts, nil
}

func addCFOpts(opts []options.ScannerOption, scannerOption ScannerOption) ([]options.ScannerOption, error) {
	if len(scannerOption.CloudFormationParamVars) > 0 {
		configFS, err := createConfigFS(scannerOption.CloudFormationParamVars)
		if err != nil {
			return nil, xerrors.Errorf("failed to create CloudFormation config FS: %w", err)
		}
		opts = append(
			opts,
			cfscanner.WithParameterFiles(scannerOption.CloudFormationParamVars...),
			cfscanner.WithConfigsFS(configFS),
		)
	}
	return opts, nil
}

func addHelmOpts(opts []options.ScannerOption, scannerOption ScannerOption) []options.ScannerOption {
	if len(scannerOption.HelmValueFiles) > 0 {
		opts = append(opts, helm.ScannerWithValuesFile(scannerOption.HelmValueFiles...))
	}

	if len(scannerOption.HelmValues) > 0 {
		opts = append(opts, helm.ScannerWithValues(scannerOption.HelmValues...))
	}

	if len(scannerOption.HelmFileValues) > 0 {
		opts = append(opts, helm.ScannerWithFileValues(scannerOption.HelmFileValues...))
	}

	if len(scannerOption.HelmStringValues) > 0 {
		opts = append(opts, helm.ScannerWithStringValues(scannerOption.HelmStringValues...))
	}

	if len(scannerOption.HelmAPIVersions) > 0 {
		opts = append(opts, helm.ScannerWithAPIVersions(scannerOption.HelmAPIVersions...))
	}

	if scannerOption.HelmKubeVersion != "" {
		opts = append(opts, helm.ScannerWithKubeVersion(scannerOption.HelmKubeVersion))
	}

	return opts
}

func createConfigFS(paths []string) (fs.FS, error) {
	mfs := mapfs.New()
	for _, path := range paths {
		if err := mfs.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, xerrors.Errorf("create dir error: %w", err)
		}
		if err := mfs.WriteFile(path, path); err != nil {
			return nil, xerrors.Errorf("write file error: %w", err)
		}
	}
	return mfs, nil
}

func CreatePolicyFS(policyPaths []string) (fs.FS, []string, error) {
	if len(policyPaths) == 0 {
		return nil, nil, nil
	}

	mfs := mapfs.New()
	for _, p := range policyPaths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to derive absolute path from '%s': %w", p, err)
		}
		fi, err := os.Stat(abs)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, xerrors.Errorf("policy file %q not found", abs)
		} else if err != nil {
			return nil, nil, xerrors.Errorf("file %q stat error: %w", abs, err)
		}

		if fi.IsDir() {
			if err = mfs.CopyFilesUnder(abs); err != nil {
				return nil, nil, xerrors.Errorf("mapfs file copy error: %w", err)
			}
		} else {
			if err := mfs.MkdirAll(filepath.Dir(abs), os.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, nil, xerrors.Errorf("mapfs mkdir error: %w", err)
			}
			if err := mfs.WriteFile(abs, abs); err != nil {
				return nil, nil, xerrors.Errorf("mapfs write error: %w", err)
			}
		}
	}

	// check paths are no longer needed as fs.FS contains only needed files now.
	policyPaths = []string{"."}

	return mfs, policyPaths, nil
}

func CreateDataFS(dataPaths []string, opts ...string) (fs.FS, []string, error) {
	fsys := mapfs.New()

	// Check if k8sVersion is provided
	if len(opts) > 0 {
		k8sVersion := opts[0]
		if err := fsys.MkdirAll("system", 0700); err != nil {
			return nil, nil, err
		}
		data := []byte(fmt.Sprintf(`{"k8s": {"version": %q}}`, k8sVersion))
		if err := fsys.WriteVirtualFile("system/k8s-version.json", data, 0600); err != nil {
			return nil, nil, err
		}
	}

	for _, path := range dataPaths {
		if err := fsys.CopyFilesUnder(path); err != nil {
			return nil, nil, err
		}
	}

	// dataPaths are no longer needed as fs.FS contains only needed files now.
	dataPaths = []string{"."}

	return fsys, dataPaths, nil
}

// ResultsToMisconf is exported for trivy-plugin-aqua purposes only
func ResultsToMisconf(configType types.ConfigType, scannerName string, results scan.Results) []types.Misconfiguration {
	misconfs := make(map[string]types.Misconfiguration)

	for _, result := range results {
		flattened := result.Flatten()

		query := fmt.Sprintf("data.%s.%s", result.RegoNamespace(), result.RegoRule())

		ruleID := result.Rule().AVDID
		if result.RegoNamespace() != "" && len(result.Rule().Aliases) > 0 {
			ruleID = result.Rule().Aliases[0]
		}

		cause := NewCauseWithCode(result, flattened)

		misconfResult := types.MisconfResult{
			Namespace: result.RegoNamespace(),
			Query:     query,
			Message:   flattened.Description,
			PolicyMetadata: types.PolicyMetadata{
				ID:                 ruleID,
				AVDID:              result.Rule().AVDID,
				Type:               fmt.Sprintf("%s Security Check", scannerName),
				Title:              result.Rule().Summary,
				Description:        result.Rule().Explanation,
				Severity:           string(flattened.Severity),
				RecommendedActions: flattened.Resolution,
				References:         flattened.Links,
			},
			CauseMetadata: cause,
			Traces:        result.Traces(),
		}

		filePath := flattened.Location.Filename
		misconf, ok := misconfs[filePath]
		if !ok {
			misconf = types.Misconfiguration{
				FileType: configType,
				FilePath: filepath.ToSlash(filePath), // defsec return OS-aware path
			}
		}

		switch flattened.Status {
		case scan.StatusPassed:
			misconf.Successes = append(misconf.Successes, misconfResult)
		case scan.StatusFailed:
			misconf.Failures = append(misconf.Failures, misconfResult)
		}

		misconfs[filePath] = misconf
	}

	return types.ToMisconfigurations(misconfs)
}

func NewCauseWithCode(underlying scan.Result, flat scan.FlatResult) types.CauseMetadata {
	cause := types.CauseMetadata{
		Resource:  flat.Resource,
		Provider:  flat.RuleProvider.DisplayName(),
		Service:   flat.RuleService,
		StartLine: flat.Location.StartLine,
		EndLine:   flat.Location.EndLine,
	}
	for _, o := range flat.Occurrences {
		cause.Occurrences = append(cause.Occurrences, types.Occurrence{
			Resource: o.Resource,
			Filename: o.Filename,
			Location: types.Location{
				StartLine: o.StartLine,
				EndLine:   o.EndLine,
			},
		})
	}

	// only failures have a code cause
	// failures can happen either due to lack of
	// OR misconfiguration of something
	if underlying.Status() == scan.StatusFailed {
		if flat.RenderedCause.Raw != "" {
			highlighted, _ := scan.Highlight(flat.Location.Filename, flat.RenderedCause.Raw, scan.DarkTheme)
			cause.RenderedCause = types.RenderedCause{
				Raw:         flat.RenderedCause.Raw,
				Highlighted: highlighted,
			}
		}

		if code, err := underlying.GetCode(); err == nil {
			cause.Code = types.Code{
				Lines: lo.Map(code.Lines, func(l scan.Line, i int) types.Line {
					return types.Line{
						Number:      l.Number,
						Content:     l.Content,
						IsCause:     l.IsCause,
						Annotation:  l.Annotation,
						Truncated:   l.Truncated,
						Highlighted: l.Highlighted,
						FirstCause:  l.FirstCause,
						LastCause:   l.LastCause,
					}
				}),
			}
		}
	}
	return cause
}
