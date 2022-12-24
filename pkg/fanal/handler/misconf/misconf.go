package misconf

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/memoryfs"

	"github.com/aquasecurity/defsec/pkg/scanners/azure/arm"

	"github.com/aquasecurity/defsec/pkg/detection"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners"
	cfscanner "github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	cfparser "github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	dfscanner "github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/helm"
	k8sscanner "github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/pkg/scanners/rbac"
	tfscanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	handler.RegisterPostHandlerInit(types.MisconfPostHandler, newMisconfPostHandler)
}

const version = 1

type misconfPostHandler struct {
	filePatterns []string
	scanners     map[string]scanners.FSScanner
}

// for a given set of paths, find the most specific filesystem path that contains all the descendants
// the function also returns a filtered version of the input paths that are compatible with a fs.FS
// using the resultant target path. This means they will always use "/" as a separator
func findFSTarget(paths []string) (string, []string, error) {
	if len(paths) == 0 {
		return "", nil, xerrors.New("must specify at least one path")
	}

	var absPaths []string
	var minSegmentCount int
	for _, relPath := range paths {
		abs, err := filepath.Abs(relPath)
		if err != nil {
			return "", nil, xerrors.Errorf("failed to derive absolute path from '%s': %w", relPath, err)
		}
		count := len(strings.Split(filepath.ToSlash(abs), "/"))
		if count < minSegmentCount || minSegmentCount == 0 {
			minSegmentCount = count
		}
		absPaths = append(absPaths, abs)
	}

	var outputSegments []string
	for i := 0; i < minSegmentCount; i++ {
		required := strings.Split(absPaths[0], string(filepath.Separator))[i]
		match := true
		for _, path := range absPaths[1:] {
			actual := strings.Split(path, string(filepath.Separator))[i]
			if required != actual {
				match = false
				break
			}
		}
		if !match {
			break
		}
		outputSegments = append(outputSegments, required)
	}

	slashTarget := strings.Join(outputSegments, "/")
	if slashTarget == "" {
		slashTarget = string(filepath.Separator)
	}

	var cleanPaths []string
	for _, path := range absPaths {
		path := filepath.ToSlash(path)
		path = strings.TrimPrefix(path, slashTarget)
		path = strings.TrimPrefix(path, "/")
		if path == "" {
			path = "."
		}
		cleanPaths = append(cleanPaths, path)
	}

	// we don't use filepath.Join here as we need to maintain the root "/"
	target := strings.Join(outputSegments, string(filepath.Separator))
	if target == "" || filepath.VolumeName(target) == target {
		target += string(filepath.Separator)
	}
	return target, cleanPaths, nil
}

func createPolicyFS(policyPaths []string) (fs.FS, []string, error) {
	if len(policyPaths) == 0 {
		return nil, nil, nil
	}
	var outsideCWD bool
	for _, path := range policyPaths {
		if strings.Contains(path, "..") || strings.HasPrefix(path, "/") || (len(path) > 1 && path[1] == ':') {
			outsideCWD = true
			break
		}
	}
	// all policy paths are inside the CWD, so create a filesystem from CWD to load from
	if !outsideCWD {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, nil, err
		}
		var cleanPaths []string
		for _, path := range policyPaths {
			path = strings.TrimPrefix(path, ".")
			path = strings.TrimPrefix(path, "/")
			cleanPaths = append(cleanPaths, path)
		}
		return os.DirFS(cwd), cleanPaths, nil
	}

	target, cleanPaths, err := findFSTarget(policyPaths)
	if err != nil {
		return nil, nil, err
	}

	return os.DirFS(target), cleanPaths, nil
}

func newMisconfPostHandler(artifactOpt artifact.Option) (handler.PostHandler, error) {
	opt := artifactOpt.MisconfScannerOption

	opts := []options.ScannerOption{
		options.ScannerWithSkipRequiredCheck(true),
		options.ScannerWithEmbeddedPolicies(!artifactOpt.MisconfScannerOption.DisableEmbeddedPolicies),
	}

	policyFS, policyPaths, err := createPolicyFS(opt.PolicyPaths)
	if err != nil {
		return nil, err
	}
	if policyFS != nil {
		opts = append(opts, options.ScannerWithPolicyFilesystem(policyFS))
	}

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

	helmOpts := addHelmOpts(opts, artifactOpt.MisconfScannerOption)
	tfOpts := addTFOpts(opts, artifactOpt.MisconfScannerOption)

	return misconfPostHandler{
		filePatterns: artifactOpt.FilePatterns,
		scanners: map[string]scanners.FSScanner{
			types.AzureARM:       arm.New(opts...),
			types.Terraform:      tfscanner.New(tfOpts...),
			types.CloudFormation: cfscanner.New(opts...),
			types.Dockerfile:     dfscanner.NewScanner(opts...),
			types.Kubernetes:     k8sscanner.NewScanner(opts...),
			types.Helm:           helm.New(helmOpts...),
			types.Rbac:           rbac.NewScanner(opts...),
		},
	}, nil
}

func addTFOpts(opts []options.ScannerOption, scannerOption config.ScannerOption) []options.ScannerOption {
	if len(scannerOption.TerraformTFVars) > 0 {
		opts = append(opts, tfscanner.ScannerWithTFVarsPaths(scannerOption.TerraformTFVars...))
	}

	return opts
}

func addHelmOpts(opts []options.ScannerOption, scannerOption config.ScannerOption) []options.ScannerOption {
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

var enabledDefsecTypes = map[detection.FileType]string{
	detection.FileTypeAzureARM:       types.AzureARM,
	detection.FileTypeCloudFormation: types.CloudFormation,
	detection.FileTypeTerraform:      types.Terraform,
	detection.FileTypeDockerfile:     types.Dockerfile,
	detection.FileTypeKubernetes:     types.Kubernetes,
	detection.FileTypeHelm:           types.Helm,
	detection.FileTypeRbac:           types.Rbac,
}

func (h misconfPostHandler) hasCustomPatternForType(t string) bool {
	for _, pattern := range h.filePatterns {
		if strings.HasPrefix(pattern, t+":") {
			return true
		}
	}
	return false
}

// Handle detects misconfigurations.
func (h misconfPostHandler) Handle(ctx context.Context, result *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	files, ok := result.Files[h.Type()]
	if !ok {
		return nil
	}

	mapMemoryFS := make(map[string]*memoryfs.FS)
	for t := range h.scanners {
		mapMemoryFS[t] = memoryfs.New()
	}

	for _, file := range files {

		for defsecType, localType := range enabledDefsecTypes {

			buffer := bytes.NewReader(file.Content)
			if !h.hasCustomPatternForType(localType) && !detection.IsType(file.Path, buffer, defsecType) {
				continue
			}
			// Replace with more detailed config type
			file.Type = localType

			if memfs, ok := mapMemoryFS[file.Type]; ok {
				if filepath.Dir(file.Path) != "." {
					if err := memfs.MkdirAll(filepath.Dir(file.Path), os.ModePerm); err != nil {
						return xerrors.Errorf("memoryfs mkdir error: %w", err)
					}
				}
				if err := memfs.WriteFile(file.Path, file.Content, os.ModePerm); err != nil {
					return xerrors.Errorf("memoryfs write error: %w", err)
				}
			}
		}
	}

	var misconfs []types.Misconfiguration
	for t, scanner := range h.scanners {
		results, err := scanner.ScanFS(ctx, mapMemoryFS[t], ".")
		if err != nil {
			if _, ok := err.(*cfparser.InvalidContentError); ok {
				log.Logger.Errorf("scan %q was broken with InvalidContentError: %v", scanner.Name(), err)
				continue
			}
			return xerrors.Errorf("scan config error: %w", err)
		}

		misconfs = append(misconfs, ResultsToMisconf(t, scanner.Name(), results)...)
	}

	// Add misconfigurations
	for _, misconf := range misconfs {
		sort.Slice(misconf.Successes, func(i, j int) bool {
			if misconf.Successes[i].AVDID == misconf.Successes[j].AVDID {
				return misconf.Successes[i].StartLine < misconf.Successes[j].StartLine
			}
			return misconf.Successes[i].AVDID < misconf.Successes[j].AVDID
		})
		sort.Slice(misconf.Warnings, func(i, j int) bool {
			if misconf.Warnings[i].AVDID == misconf.Warnings[j].AVDID {
				return misconf.Warnings[i].StartLine < misconf.Warnings[j].StartLine
			}
			return misconf.Warnings[i].AVDID < misconf.Warnings[j].AVDID
		})
		sort.Slice(misconf.Failures, func(i, j int) bool {
			if misconf.Failures[i].AVDID == misconf.Failures[j].AVDID {
				return misconf.Failures[i].StartLine < misconf.Failures[j].StartLine
			}
			return misconf.Failures[i].AVDID < misconf.Failures[j].AVDID
		})
	}

	blob.Misconfigurations = misconfs

	return nil
}

func (h misconfPostHandler) Version() int {
	return version
}

func (h misconfPostHandler) Type() types.HandlerType {
	return types.MisconfPostHandler
}

func (h misconfPostHandler) Priority() int {
	return types.MisconfPostHandlerPriority
}

// This function is exported for trivy-plugin-aqua purposes only
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
				FilePath: filePath,
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
