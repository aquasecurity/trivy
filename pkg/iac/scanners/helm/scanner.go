package helm

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
	kparser "github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	mu            sync.Mutex
	logger        *log.Logger
	options       []options.ScannerOption
	parserOptions []parser.Option
	regoScanner   *rego.Scanner
}

func (s *Scanner) SetIncludeDeprecatedChecks(bool)                {}
func (s *Scanner) SetRegoOnly(bool)                               {}
func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {}

// New creates a new Scanner
func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		options: opts,
		logger:  log.WithPrefix("helm scanner"),
	}

	for _, option := range opts {
		option(s)
	}
	return s
}

func (s *Scanner) addParserOptions(opts ...parser.Option) {
	s.parserOptions = append(s.parserOptions, opts...)
}

func (s *Scanner) Name() string {
	return "Helm"
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, root string) (scan.Results, error) {

	if err := s.initRegoScanner(fsys); err != nil {
		return nil, fmt.Errorf("failed to init rego scanner: %w", err)
	}

	p, err := parser.New(s.parserOptions...)
	if err != nil {
		return nil, err
	}

	files, err := p.ParseFS(ctx, fsys, root)
	if err != nil {
		return nil, err
	}

	var results scan.Results

	for _, file := range files {
		file := file
		s.logger.Debug("Processing rendered chart file", log.FilePath(file.Path))

		manifests, err := kparser.Parse(ctx, strings.NewReader(file.Content), file.Path)
		if err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		for _, manifest := range manifests {
			fileResults, err := s.regoScanner.ScanInput(ctx, rego.Input{
				Path:     file.Path,
				Contents: manifest,
				FS:       fsys,
			})
			if err != nil {
				return nil, fmt.Errorf("scanning error: %w", err)
			}

			if len(fileResults) > 0 {
				renderedFS := memoryfs.New()
				if err := renderedFS.MkdirAll(filepath.Dir(file.Path), fs.ModePerm); err != nil {
					return nil, err
				}
				if err := renderedFS.WriteLazyFile(file.Path, func() (io.Reader, error) {
					return strings.NewReader(file.Content), nil
				}, fs.ModePerm); err != nil {
					return nil, err
				}

				fileResults.SetSourceAndFilesystem(file.ChartPath, renderedFS, detection.IsArchive(file.ChartPath))
			}

			results = append(results, fileResults...)
		}

	}

	return results, nil

}

func (s *Scanner) initRegoScanner(srcFS fs.FS) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return nil
	}
	regoScanner := rego.NewScanner(types.SourceKubernetes, s.options...)
	if err := regoScanner.LoadPolicies(srcFS); err != nil {
		return err
	}
	s.regoScanner = regoScanner
	return nil
}
