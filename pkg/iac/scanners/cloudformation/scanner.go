package cloudformation

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"sync"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
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
	mu                      sync.Mutex
	logger                  *log.Logger
	parser                  *parser.Parser
	regoScanner             *rego.Scanner
	regoOnly                bool
	options                 []options.ScannerOption
	parserOptions           []parser.Option
	frameworks              []framework.Framework
	includeDeprecatedChecks bool
}

func (s *Scanner) SetIncludeDeprecatedChecks(b bool) {
	s.includeDeprecatedChecks = b
}

func (s *Scanner) addParserOption(opt parser.Option) {
	s.parserOptions = append(s.parserOptions, opt)
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetRegoOnly(regoOnly bool) {
	s.regoOnly = regoOnly
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

func (s *Scanner) initRegoScanner(srcFS fs.FS) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return nil
	}
	regoScanner := rego.NewScanner(s.options...)
	if err := regoScanner.LoadPolicies(srcFS); err != nil {
		return err
	}
	s.regoScanner = regoScanner
	return nil
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (results scan.Results, err error) {

	contexts, err := s.parser.ParseFS(ctx, fsys, dir)
	if err != nil {
		return nil, err
	}

	if len(contexts) == 0 {
		return nil, nil
	}

	if err := s.initRegoScanner(fsys); err != nil {
		return nil, err
	}

	for _, cfCtx := range contexts {
		if cfCtx == nil {
			continue
		}
		fileResults, err := s.scanFileContext(ctx, cfCtx, fsys)
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

	if err := s.initRegoScanner(fsys); err != nil {
		return nil, err
	}

	results, err := s.scanFileContext(ctx, cfCtx, fsys)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", fsys, false)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}

func (s *Scanner) scanFileContext(ctx context.Context, cfCtx *parser.FileContext, fsys fs.FS) (results scan.Results, err error) {
	state := adapter.Adapt(*cfCtx)
	if state == nil {
		return nil, nil
	}
	if !s.regoOnly {
		for _, rule := range rules.GetRegistered(s.frameworks...) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			if !s.includeDeprecatedChecks && rule.Deprecated {
				continue // skip deprecated checks
			}

			evalResult := rule.Evaluate(state)
			if len(evalResult) > 0 {
				for _, scanResult := range evalResult {

					ref := scanResult.Metadata().Reference()

					if ref == "" && scanResult.Metadata().Parent() != nil {
						ref = scanResult.Metadata().Parent().Reference()
					}

					description := getDescription(scanResult, ref)
					scanResult.OverrideDescription(description)
					results = append(results, scanResult)
				}
			}
		}
	}
	regoResults, err := s.regoScanner.ScanInput(ctx, types.SourceCloud, rego.Input{
		Path:     cfCtx.Metadata().Range().GetFilename(),
		FS:       fsys,
		Contents: state.ToRego(),
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}
	results = append(results, regoResults...)

	results.Ignore(cfCtx.Ignores, nil)

	for _, ignored := range results.GetIgnored() {
		s.logger.Info("Ignore finding",
			log.String("rule", ignored.Rule().LongID()),
			log.String("range", ignored.Range().String()),
		)
	}

	return results, nil
}

func getDescription(scanResult scan.Result, ref string) string {
	switch scanResult.Status() {
	case scan.StatusPassed:
		return fmt.Sprintf("Resource '%s' passed check: %s", ref, scanResult.Rule().Summary)
	case scan.StatusIgnored:
		return fmt.Sprintf("Resource '%s' had check ignored: %s", ref, scanResult.Rule().Summary)
	default:
		return scanResult.Description()
	}
}
