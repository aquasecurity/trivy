package cloudformation

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"sync"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func WithParameters(params map[string]any) options.ScannerOption {
	return func(cs options.ConfigurableScanner) {
		if s, ok := cs.(*Scanner); ok {
			s.addParserOptions(parser2.WithParameters(params))
		}
	}
}

func WithParameterFiles(files ...string) options.ScannerOption {
	return func(cs options.ConfigurableScanner) {
		if s, ok := cs.(*Scanner); ok {
			s.addParserOptions(parser2.WithParameterFiles(files...))
		}
	}
}

func WithConfigsFS(fsys fs.FS) options.ScannerOption {
	return func(cs options.ConfigurableScanner) {
		if s, ok := cs.(*Scanner); ok {
			s.addParserOptions(parser2.WithConfigsFS(fsys))
		}
	}
}

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct { // nolint: gocritic
	debug                 debug.Logger
	policyDirs            []string
	policyReaders         []io.Reader
	parser                *parser2.Parser
	regoScanner           *rego.Scanner
	skipRequired          bool
	regoOnly              bool
	loadEmbeddedPolicies  bool
	loadEmbeddedLibraries bool
	options               []options.ScannerOption
	parserOptions         []options.ParserOption
	frameworks            []framework.Framework
	spec                  string
	sync.Mutex
}

func (s *Scanner) addParserOptions(opt options.ParserOption) {
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

func (s *Scanner) SetSkipRequiredCheck(skip bool) {
	s.skipRequired = skip
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "cloudformation", "scanner")
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
	}
	for _, opt := range opts {
		opt(s)
	}
	s.addParserOptions(options.ParserWithSkipRequiredCheck(s.skipRequired))
	s.parser = parser2.New(s.parserOptions...)
	return s
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(types.SourceCloud, s.options...)
	regoScanner.SetParentDebugLogger(s.debug)
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

func (s *Scanner) scanFileContext(ctx context.Context, regoScanner *rego.Scanner, cfCtx *parser2.FileContext, fsys fs.FS) (results scan.Results, err error) {
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
			if rule.GetRule().RegoPackage != "" {
				continue
			}
			evalResult := rule.Evaluate(state)
			if len(evalResult) > 0 {
				s.debug.Log("Found %d results for %s", len(evalResult), rule.GetRule().AVDID)
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
	return append(results, regoResults...), nil
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
