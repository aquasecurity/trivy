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
	"github.com/aquasecurity/memoryfs"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
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
}

type Scanner struct {
	filePatterns []string
	scanners     map[string]scanners.FSScanner
}

func NewScanner(filePatterns []string, opt config.ScannerOption) (Scanner, error) {
	opts := []options.ScannerOption{
		options.ScannerWithSkipRequiredCheck(true),
		options.ScannerWithEmbeddedPolicies(!opt.DisableEmbeddedPolicies),
	}

	policyFS, policyPaths, err := createPolicyFS(opt.PolicyPaths)
	if err != nil {
		return Scanner{}, err
	}
	if policyFS != nil {
		opts = append(opts, options.ScannerWithPolicyFilesystem(policyFS))
	}

	dataFS, dataPaths, err := createDataFS(opt.DataPaths, opt.K8sVersion)
	if err != nil {
		return Scanner{}, err
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

	helmOpts := addHelmOpts(opts, opt)
	tfOpts := addTFOpts(opts, opt)

	return Scanner{
		filePatterns: filePatterns,
		scanners: map[string]scanners.FSScanner{
			types.AzureARM:       arm.New(opts...),
			types.Terraform:      tfscanner.New(tfOpts...),
			types.CloudFormation: cfscanner.New(opts...),
			types.Dockerfile:     dfscanner.NewScanner(opts...),
			types.Kubernetes:     k8sscanner.NewScanner(opts...),
			types.Helm:           helm.New(helmOpts...),
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

func createPolicyFS(policyPaths []string) (fs.FS, []string, error) {
	if len(policyPaths) == 0 {
		return nil, nil, nil
	}

	mfs := mapfs.New()
	for _, p := range policyPaths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to derive absolute path from '%s': %w", p, err)
		}
		if err = mfs.CopyFilesUnder(abs); err != nil {
			return nil, nil, xerrors.Errorf("mapfs file copy error: %w", err)
		}
	}

	// policy paths are no longer needed as fs.FS contains only needed files now.
	policyPaths = []string{"."}

	return mfs, policyPaths, nil
}

func createDataFS(dataPaths []string, k8sVersion string) (fs.FS, []string, error) {
	fsys := mapfs.New()

	// Create a virtual file for Kubernetes scanning
	if k8sVersion != "" {
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

	// data paths are no longer needed as fs.FS contains only needed files now.
	dataPaths = []string{"."}

	return fsys, dataPaths, nil
}

func (s *Scanner) hasCustomPatternForType(t string) bool {
	for _, pattern := range s.filePatterns {
		if strings.HasPrefix(pattern, t+":") {
			return true
		}
	}
	return false
}

// Scan detects misconfigurations.
func (s *Scanner) Scan(ctx context.Context, files []types.File) ([]types.Misconfiguration, error) {
	mapMemoryFS := make(map[string]*memoryfs.FS)
	for t := range s.scanners {
		mapMemoryFS[t] = memoryfs.New()
	}

	for _, file := range files {
		for defsecType, localType := range enabledDefsecTypes {
			buffer := bytes.NewReader(file.Content)
			if !s.hasCustomPatternForType(localType) && !detection.IsType(file.Path, buffer, defsecType) {
				continue
			}
			// Replace with more detailed config type
			file.Type = localType

			if memfs, ok := mapMemoryFS[file.Type]; ok {
				if filepath.Dir(file.Path) != "." {
					if err := memfs.MkdirAll(filepath.Dir(file.Path), os.ModePerm); err != nil {
						return nil, xerrors.Errorf("memoryfs mkdir error: %w", err)
					}
				}
				if err := memfs.WriteFile(file.Path, file.Content, os.ModePerm); err != nil {
					return nil, xerrors.Errorf("memoryfs write error: %w", err)
				}
			}
		}
	}

	var misconfs []types.Misconfiguration
	for t, scanner := range s.scanners {
		results, err := scanner.ScanFS(ctx, mapMemoryFS[t], ".")
		if err != nil {
			if _, ok := err.(*cfparser.InvalidContentError); ok {
				log.Logger.Errorf("scan %q was broken with InvalidContentError: %v", scanner.Name(), err)
				continue
			}
			return nil, xerrors.Errorf("scan config error: %w", err)
		}

		misconfs = append(misconfs, ResultsToMisconf(t, scanner.Name(), results)...)
	}

	// Sort misconfigurations
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

	return misconfs, nil
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
