package misconf

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/defsec/pkg/detection"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners"
	"github.com/aquasecurity/defsec/pkg/scanners/azure/arm"
	cfscanner "github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	cfparser "github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	dfscanner "github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/helm"
	k8sscanner "github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	tfscanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	tfpscanner "github.com/aquasecurity/defsec/pkg/scanners/terraformplan"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

var enabledDefsecTypes = map[detection.FileType]string{
	detection.FileTypeAzureARM:       types.AzureARM,
	detection.FileTypeCloudFormation: types.CloudFormation,
	detection.FileTypeTerraform:      types.Terraform,
	detection.FileTypeDockerfile:     types.Dockerfile,
	detection.FileTypeKubernetes:     types.Kubernetes,
	detection.FileTypeHelm:           types.Helm,
	detection.FileTypeTerraformPlan:  types.TerraformPlan,
}

type ScannerOption struct {
	Trace                    bool
	RegoOnly                 bool
	Namespaces               []string
	PolicyPaths              []string
	DataPaths                []string
	DisableEmbeddedPolicies  bool
	DisableEmbeddedLibraries bool

	HelmValues          []string
	HelmValueFiles      []string
	HelmFileValues      []string
	HelmStringValues    []string
	TerraformTFVars     []string
	TfExcludeDownloaded bool
	K8sVersion          string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

type Scanner struct {
	fileType       detection.FileType
	scanner        scanners.FSScanner
	hasFilePattern bool
}

func NewAzureARMScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return newScanner(detection.FileTypeAzureARM, filePatterns, opt)
}

func NewCloudFormationScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return newScanner(detection.FileTypeCloudFormation, filePatterns, opt)
}

func NewDockerfileScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return newScanner(detection.FileTypeDockerfile, filePatterns, opt)
}

func NewHelmScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return newScanner(detection.FileTypeHelm, filePatterns, opt)
}

func NewKubernetesScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return newScanner(detection.FileTypeKubernetes, filePatterns, opt)
}

func NewTerraformScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return newScanner(detection.FileTypeTerraform, filePatterns, opt)
}

func NewTerraformPlanScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return newScanner(detection.FileTypeTerraformPlan, filePatterns, opt)
}

func newScanner(t detection.FileType, filePatterns []string, opt ScannerOption) (*Scanner, error) {
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
		scanner = tfscanner.New(opts...)
	case detection.FileTypeTerraformPlan:
		scanner = tfpscanner.New(opts...)
	}

	return &Scanner{
		fileType:       t,
		scanner:        scanner,
		hasFilePattern: hasFilePattern(t, filePatterns),
	}, nil
}

func (s *Scanner) Scan(ctx context.Context, fsys fs.FS) ([]types.Misconfiguration, error) {
	newfs, err := s.filterFS(fsys)
	if err != nil {
		return nil, xerrors.Errorf("fs filter error: %w", err)
	} else if newfs == nil {
		// Skip scanning if no relevant files are found
		return nil, nil
	}

	log.Logger.Debugf("Scanning %s files for misconfigurations...", s.scanner.Name())
	results, err := s.scanner.ScanFS(ctx, newfs, ".")
	if err != nil {
		if _, ok := err.(*cfparser.InvalidContentError); ok {
			log.Logger.Errorf("scan %q was broken with InvalidContentError: %v", s.scanner.Name(), err)
			return nil, nil
		}
		return nil, xerrors.Errorf("scan config error: %w", err)
	}

	configType := enabledDefsecTypes[s.fileType]
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

	var foundRelevantFile bool
	filter := func(path string, d fs.DirEntry) (bool, error) {
		file, err := fsys.Open(path)
		if err != nil {
			return false, err
		}
		rs, ok := file.(io.ReadSeeker)
		if !ok {
			return false, xerrors.Errorf("type assertion error: %w", err)
		}
		defer file.Close()

		if !s.hasFilePattern && !detection.IsType(path, rs, s.fileType) {
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
	opts := []options.ScannerOption{
		options.ScannerWithSkipRequiredCheck(true),
		options.ScannerWithEmbeddedPolicies(!opt.DisableEmbeddedPolicies),
		options.ScannerWithEmbeddedLibraries(!opt.DisableEmbeddedLibraries),
	}

	policyFS, policyPaths, err := CreatePolicyFS(opt.PolicyPaths)
	if err != nil {
		return nil, err
	}
	if policyFS != nil {
		opts = append(opts, options.ScannerWithPolicyFilesystem(policyFS))
	}

	dataFS, dataPaths, err := CreateDataFS(opt.DataPaths, opt.K8sVersion)
	if err != nil {
		return nil, err
	}
	opts = append(opts, options.ScannerWithDataDirs(dataPaths...))
	opts = append(opts, options.ScannerWithDataFilesystem(dataFS))

	if opt.Trace {
		opts = append(opts, options.ScannerWithPerResultTracing(true))
	}

	if opt.RegoOnly {
		opts = append(opts, options.ScannerWithRegoOnly(true))
	}

	if len(policyPaths) > 0 {
		opts = append(opts, options.ScannerWithPolicyDirs(policyPaths...))
	}

	if len(opt.DataPaths) > 0 {
		opts = append(opts, options.ScannerWithDataDirs(opt.DataPaths...))
	}

	if len(opt.Namespaces) > 0 {
		opts = append(opts, options.ScannerWithPolicyNamespaces(opt.Namespaces...))
	}

	switch t {
	case detection.FileTypeHelm:
		return addHelmOpts(opts, opt), nil
	case detection.FileTypeTerraform:
		return addTFOpts(opts, opt), nil
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

func addTFOpts(opts []options.ScannerOption, scannerOption ScannerOption) []options.ScannerOption {
	if len(scannerOption.TerraformTFVars) > 0 {
		opts = append(opts, tfscanner.ScannerWithTFVarsPaths(scannerOption.TerraformTFVars...))
	}

	opts = append(opts, tfscanner.ScannerWithAllDirectories(true))
	opts = append(opts, tfscanner.ScannerWithSkipDownloaded(scannerOption.TfExcludeDownloaded))

	return opts
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

	return opts
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

	// policy paths are no longer needed as fs.FS contains only needed files now.
	policyPaths = []string{"."}

	return mfs, policyPaths, nil
}

func CreateDataFS(dataPaths []string, options ...string) (fs.FS, []string, error) {
	fsys := mapfs.New()

	// Check if k8sVersion is provided
	if len(options) > 0 {
		k8sVersion := options[0]
		if err := fsys.MkdirAll("system", 0700); err != nil {
			return nil, nil, err
		}
		data := []byte(fmt.Sprintf(`{"k8s": {"version": "%s"}}`, k8sVersion))
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
func ResultsToMisconf(configType string, scannerName string, results scan.Results) []types.Misconfiguration {
	misconfs := map[string]types.Misconfiguration{}

	for _, result := range results {
		flattened := result.Flatten()

		query := fmt.Sprintf("data.%s.%s", result.RegoNamespace(), result.RegoRule())

		ruleID := result.Rule().AVDID
		if result.RegoNamespace() != "" && len(result.Rule().Aliases) > 0 {
			ruleID = result.Rule().Aliases[0]
		}

		cause := NewCauseWithCode(result)

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

		if flattened.Warning {
			misconf.Warnings = append(misconf.Warnings, misconfResult)
		} else {
			switch flattened.Status {
			case scan.StatusPassed:
				misconf.Successes = append(misconf.Successes, misconfResult)
			case scan.StatusIgnored:
				misconf.Exceptions = append(misconf.Exceptions, misconfResult)
			case scan.StatusFailed:
				misconf.Failures = append(misconf.Failures, misconfResult)
			}
		}
		misconfs[filePath] = misconf
	}

	return types.ToMisconfigurations(misconfs)
}

func NewCauseWithCode(underlying scan.Result) types.CauseMetadata {
	flat := underlying.Flatten()
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
	return cause
}
