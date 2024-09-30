package yaml

import (
	"context"
	"io/fs"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/yaml/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	mu          sync.Mutex
	options     []options.ScannerOption
	logger      *log.Logger
	parser      *parser.Parser
	regoScanner *rego.Scanner
}

func (s *Scanner) SetIncludeDeprecatedChecks(bool)                {}
func (s *Scanner) SetRegoOnly(bool)                               {}
func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {}

func (s *Scanner) Name() string {
	return "YAML"
}

func NewScanner(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		options: opts,
		logger:  log.WithPrefix("yaml scanner"),
		parser:  parser.New(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, path string) (scan.Results, error) {

	fileset, err := s.parser.ParseFS(ctx, fsys, path)
	if err != nil {
		return nil, err
	}

	if len(fileset) == 0 {
		return nil, nil
	}

	var inputs []rego.Input
	for path, files := range fileset {
		for _, file := range files {
			inputs = append(inputs, rego.Input{
				Path:     path,
				Contents: file,
				FS:       fsys,
			})
		}
	}

	results, err := s.scanRego(ctx, fsys, inputs...)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) ScanFile(ctx context.Context, fsys fs.FS, path string) (scan.Results, error) {
	parsed, err := s.parser.ParseFile(ctx, fsys, path)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("Scanning", log.String("path", path))
	return s.scanRego(ctx, fsys, rego.Input{
		Path:     path,
		Contents: parsed,
	})
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(types.SourceYAML, s.options...)
	if err := regoScanner.LoadPolicies(srcFS); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) scanRego(ctx context.Context, srcFS fs.FS, inputs ...rego.Input) (scan.Results, error) {
	regoScanner, err := s.initRegoScanner(srcFS)
	if err != nil {
		return nil, err
	}
	results, err := regoScanner.ScanInput(ctx, inputs...)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", srcFS, false)
	return results, nil
}
