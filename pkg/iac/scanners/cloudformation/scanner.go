package cloudformation

import (
	"context"
	"fmt"
	"io/fs"

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
	*rego.RegoScannerProvider
	logger        *log.Logger
	parser        *parser.Parser
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
		RegoScannerProvider: rego.NewRegoScannerProvider(opts...),
		options:             opts,
		logger:              log.WithPrefix("cloudformation scanner"),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.parser = parser.New(s.parserOptions...)
	return s
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (results scan.Results, err error) {

	contexts, err := s.parser.ParseFS(ctx, fsys, dir)
	if err != nil {
		return nil, err
	}

	if len(contexts) == 0 {
		return nil, nil
	}

	rs, err := s.InitRegoScanner(fsys, s.options)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	for _, cfCtx := range contexts {
		if cfCtx == nil {
			continue
		}
		fileResults, err := s.scanFileContext(ctx, rs, cfCtx, fsys)
		if err != nil {
			return nil, err
		}
		results = append(results, fileResults...)
	}
	return results, nil
}

func (s *Scanner) scanFileContext(ctx context.Context, regoScanner *rego.Scanner, cfCtx *parser.FileContext, fsys fs.FS) (scan.Results, error) {
	state := adapter.Adapt(*cfCtx)
	if state == nil {
		return nil, nil
	}

	results, err := regoScanner.ScanInput(ctx, types.SourceCloud, rego.Input{
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
			log.String("rule", ignored.Rule().CanonicalID()),
			log.String("range", ignored.Range().String()),
		)
	}

	return results, nil
}
