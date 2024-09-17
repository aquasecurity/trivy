package cloudformation

import (
	"context"
	"fmt"
	"io"
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
	policyDirs              []string
	policyReaders           []io.Reader
	parser                  *parser.Parser
	regoScanner             *rego.Scanner
	regoOnly                bool
	loadEmbeddedPolicies    bool
	loadEmbeddedLibraries   bool
	options                 []options.ScannerOption
	parserOptions           []parser.Option
	frameworks              []framework.Framework
	spec                    string
	includeDeprecatedChecks bool
}

func (s *Scanner) SetIncludeDeprecatedChecks(b bool) {
	s.includeDeprecatedChecks = b
}

func (s *Scanner) SetCustomSchemas(map[string][]byte) {}

func (s *Scanner) addParserOption(opt parser.Option) {
	s.parserOptions = append(s.parserOptions, opt)
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbeddedPolicies = b
}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	s.loadEmbeddedLibraries = b
}

func (s *Scanner) SetRegoOnly(regoOnly bool) {
	s.regoOnly = regoOnly
}

func (s *Scanner) Name() string {
	return "CloudFormation"
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetPolicyFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}

func (s *Scanner) SetDataFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}
func (s *Scanner) SetRegoErrorLimit(_ int) {}

func (s *Scanner) SetTraceWriter(_ io.Writer)        {}
func (s *Scanner) SetPerResultTracingEnabled(_ bool) {}
func (s *Scanner) SetDataDirs(_ ...string)           {}
func (s *Scanner) SetPolicyNamespaces(_ ...string)   {}

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
	if err := regoScanner.LoadPolicies(s.loadEmbeddedLibraries, s.loadEmbeddedPolicies, srcFS, s.policyDirs, s.policyReaders); err != nil {
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

func (s *Scanner) scanFileContext(ctx context.Context, regoScanner *rego.Scanner, cfCtx *parser.FileContext, fsys fs.FS) (results scan.Results, err error) {
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
	regoResults, err := regoScanner.ScanInput(ctx, rego.Input{
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
