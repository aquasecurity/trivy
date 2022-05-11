package misconf

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/detection"

	"github.com/liamg/memoryfs"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners"
	cfscanner "github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	dfscanner "github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	k8sscanner "github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	tfscanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.MisconfPostHandler, newMisconfPostHandler)
}

const version = 1

type misconfPostHandler struct {
	scanners map[string]scanners.Scanner
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
		path = strings.TrimPrefix(path, string(filepath.Separator))
		if path == "" {
			path = "."
		}
		cleanPaths = append(cleanPaths, path)
	}

	// we don't use filepath.Join here as we need to maintain the root "/"
	target := strings.Join(outputSegments, string(filepath.Separator))
	if target == "" {
		target = string(filepath.Separator)
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
		opts = append(opts, tfscanner.ScannerWithRegoOnly(true))
		opts = append(opts, cfscanner.ScannerWithRegoOnly(true))
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

	return misconfPostHandler{
		scanners: map[string]scanners.Scanner{
			types.Terraform:      tfscanner.New(opts...),
			types.CloudFormation: cfscanner.New(opts...),
			types.Dockerfile:     dfscanner.NewScanner(opts...),
			types.Kubernetes:     k8sscanner.NewScanner(opts...),
		},
	}, nil
}

var enabledDefsecTypes = map[detection.FileType]string{
	detection.FileTypeCloudFormation: types.CloudFormation,
	detection.FileTypeTerraform:      types.Terraform,
	detection.FileTypeDockerfile:     types.Dockerfile,
	detection.FileTypeKubernetes:     types.Kubernetes,
}

// Handle detects misconfigurations.
func (h misconfPostHandler) Handle(ctx context.Context, result *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	files, ok := result.Files[h.Type()]
	if !ok {
		return nil
	}

	mapMemoryFS := map[string]*memoryfs.FS{
		types.Terraform:      memoryfs.New(),
		types.CloudFormation: memoryfs.New(),
		types.Dockerfile:     memoryfs.New(),
		types.Kubernetes:     memoryfs.New(),
	}

	for _, file := range files {

		for defsecType, localType := range enabledDefsecTypes {

			buffer := bytes.NewReader(file.Content)
			if !detection.IsType(file.Path, buffer, defsecType) {
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
			return xerrors.Errorf("scan config error: %w", err)
		}

		misconfs = append(misconfs, resultsToMisconf(t, scanner.Name(), results)...)
	}

	// Add misconfigurations
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

func resultsToMisconf(configType string, scannerName string, results scan.Results) []types.Misconfiguration {
	misconfs := map[string]types.Misconfiguration{}

	for _, result := range results {
		flattened := result.Flatten()

		query := fmt.Sprintf("data.%s.%s", result.RegoNamespace(), result.RegoRule())

		ruleID := result.Rule().LegacyID
		if ruleID == "" {
			ruleID = result.Rule().AVDID
		}

		cause := types.NewCauseWithCode(result)

		misconfResult := types.MisconfResult{
			Namespace: result.RegoNamespace(),
			Query:     query,
			Message:   flattened.Description,
			PolicyMetadata: types.PolicyMetadata{
				ID:                 ruleID,
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
