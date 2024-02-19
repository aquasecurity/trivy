package helm

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
	kparser "github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	policyDirs            []string
	dataDirs              []string
	debug                 debug.Logger
	options               []options.ScannerOption
	parserOptions         []options.ParserOption
	policyReaders         []io.Reader
	loadEmbeddedLibraries bool
	loadEmbeddedPolicies  bool
	policyFS              fs.FS
	skipRequired          bool
	frameworks            []framework.Framework
	spec                  string
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) SetRegoOnly(bool) {
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

// New creates a new Scanner
func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		options: opts,
	}

	for _, option := range opts {
		option(s)
	}
	return s
}

func (s *Scanner) AddParserOptions(opts ...options.ParserOption) {
	s.parserOptions = append(s.parserOptions, opts...)
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbeddedPolicies = b
}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	s.loadEmbeddedLibraries = b
}

func (s *Scanner) Name() string {
	return "Helm"
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetSkipRequiredCheck(skip bool) {
	s.skipRequired = skip
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "helm", "scanner")
}

func (s *Scanner) SetTraceWriter(_ io.Writer) {
	// handled by rego later - nothing to do for now...
}

func (s *Scanner) SetPerResultTracingEnabled(_ bool) {
	// handled by rego later - nothing to do for now...
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetDataDirs(dirs ...string) {
	s.dataDirs = dirs
}

func (s *Scanner) SetPolicyNamespaces(namespaces ...string) {
	// handled by rego later - nothing to do for now...
}

func (s *Scanner) SetPolicyFilesystem(policyFS fs.FS) {
	s.policyFS = policyFS
}

func (s *Scanner) SetDataFilesystem(_ fs.FS) {}
func (s *Scanner) SetRegoErrorLimit(_ int)   {}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, path string) (scan.Results, error) {

	var results []scan.Result
	if err := fs.WalkDir(target, path, func(path string, d fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if detection.IsArchive(path) {
			if scanResults, err := s.getScanResults(path, ctx, target); err != nil {
				return err
			} else {
				results = append(results, scanResults...)
			}
		}

		if strings.HasSuffix(path, "Chart.yaml") {
			if scanResults, err := s.getScanResults(filepath.Dir(path), ctx, target); err != nil {
				return err
			} else {
				results = append(results, scanResults...)
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return results, nil

}

func (s *Scanner) getScanResults(path string, ctx context.Context, target fs.FS) (results []scan.Result, err error) {
	helmParser := parser.New(path, s.parserOptions...)

	if err := helmParser.ParseFS(ctx, target, path); err != nil {
		return nil, err
	}

	chartFiles, err := helmParser.RenderedChartFiles()
	if err != nil { // not valid helm, maybe some other yaml etc., abort
		s.debug.Log("Failed to render Chart files: %s", err)
		return nil, nil
	}

	regoScanner := rego.NewScanner(types.SourceKubernetes, s.options...)
	policyFS := target
	if s.policyFS != nil {
		policyFS = s.policyFS
	}
	if err := regoScanner.LoadPolicies(s.loadEmbeddedLibraries, s.loadEmbeddedPolicies, policyFS, s.policyDirs, s.policyReaders); err != nil {
		return nil, fmt.Errorf("policies load: %w", err)
	}
	for _, file := range chartFiles {
		file := file
		s.debug.Log("Processing rendered chart file: %s", file.TemplateFilePath)

		manifests, err := kparser.New().Parse(strings.NewReader(file.ManifestContent), file.TemplateFilePath)
		if err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		for _, manifest := range manifests {
			fileResults, err := regoScanner.ScanInput(ctx, rego.Input{
				Path:     file.TemplateFilePath,
				Contents: manifest,
				FS:       target,
			})
			if err != nil {
				return nil, fmt.Errorf("scanning error: %w", err)
			}

			if len(fileResults) > 0 {
				renderedFS := memoryfs.New()
				if err := renderedFS.MkdirAll(filepath.Dir(file.TemplateFilePath), fs.ModePerm); err != nil {
					return nil, err
				}
				if err := renderedFS.WriteLazyFile(file.TemplateFilePath, func() (io.Reader, error) {
					return strings.NewReader(file.ManifestContent), nil
				}, fs.ModePerm); err != nil {
					return nil, err
				}
				fileResults.SetSourceAndFilesystem(helmParser.ChartSource, renderedFS, detection.IsArchive(helmParser.ChartSource))
			}

			results = append(results, fileResults...)
		}

	}
	return results, nil
}
