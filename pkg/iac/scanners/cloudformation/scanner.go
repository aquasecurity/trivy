package cloudformation

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"sync"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func WithParameters(params map[string]any) options.ScannerOption {
	return func(cs options.ConfigurableScanner) {
		if s, ok := cs.(*Scanner); ok {
			s.addParserOption(parser.WithParameters(params))
		}
	}
}

func WithParameterFiles(files ...string) options.ScannerOption {
	return func(cs options.ConfigurableScanner) {
		if s, ok := cs.(*Scanner); ok {
			s.addParserOption(parser.WithParameterFiles(files...))
		}
	}
}

func WithConfigsFS(fsys fs.FS) options.ScannerOption {
	return func(cs options.ConfigurableScanner) {
		if s, ok := cs.(*Scanner); ok {
			s.addParserOption(parser.WithConfigsFS(fsys))
		}
	}
}

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	mu            sync.Mutex
	logger        *log.Logger
	parser        *parser.Parser
	regoScanner   *rego.Scanner
	options       []options.ScannerOption
	parserOptions []parser.Option
}

func (s *Scanner) addParserOption(opt parser.Option) {
	s.parserOptions = append(s.parserOptions, opt)
}

func (s *Scanner) Name() string {
	return "CloudFormation"
}

// New creates a new Scanner
func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		options: opts,
		logger:  log.WithPrefix("cloudformation scanner"),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.parser = parser.New(s.parserOptions...)
	return s
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(types.SourceCloud, s.options...)
	if err := regoScanner.LoadPolicies(srcFS); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (results scan.Results, err error) {

	contexts, err := s.parser.ParseFS(ctx, fsys, dir)
	if err != nil {
		return nil, err
	}

	if len(contexts) == 0 {
		return nil, nil
	}

	regoScanner, err := s.initRegoScanner(fsys)
	if err != nil {
		return nil, err
	}

	for _, cfCtx := range contexts {
		if cfCtx == nil {
			continue
		}
		fileResults, err := s.scanFileContext(ctx, regoScanner, cfCtx, fsys)
		if err != nil {
			return nil, err
		}
		results = append(results, fileResults...)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}

func (s *Scanner) ScanFile(ctx context.Context, fsys fs.FS, path string) (scan.Results, error) {

	cfCtx, err := s.parser.ParseFile(ctx, fsys, path)
	if err != nil {
		return nil, err
	}

	regoScanner, err := s.initRegoScanner(fsys)
	if err != nil {
		return nil, err
	}

	results, err := s.scanFileContext(ctx, regoScanner, cfCtx, fsys)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", fsys, false)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}

func (s *Scanner) scanFileContext(ctx context.Context, regoScanner *rego.Scanner, cfCtx *parser.FileContext, fsys fs.FS) (scan.Results, error) {
	state := adapter.Adapt(*cfCtx)
	if state == nil {
		return nil, nil
	}

	results, err := regoScanner.ScanInput(ctx, rego.Input{
		Path:     cfCtx.Metadata().Range().GetFilename(),
		FS:       fsys,
		Contents: state.ToRego(),
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}

	// ignore a result based on user input
	results.Ignore(cfCtx.Ignores, nil)

	for _, ignored := range results.GetIgnored() {
		s.logger.Info("Ignore finding",
			log.String("rule", ignored.Rule().LongID()),
			log.String("range", ignored.Range().String()),
		)
	}

	return results, nil
}
