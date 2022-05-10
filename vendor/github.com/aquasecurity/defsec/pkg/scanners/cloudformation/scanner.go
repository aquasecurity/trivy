package cloudformation

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"sync"

	"github.com/aquasecurity/defsec/internal/debug"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"

	"github.com/aquasecurity/defsec/pkg/scan"

	adapter "github.com/aquasecurity/defsec/internal/adapters/cloudformation"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/rego"
	_ "github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scanners"
)

var _ scanners.Scanner = (*Scanner)(nil)
var _ ConfigurableCloudFormationScanner = (*Scanner)(nil)

type Scanner struct {
	debug         debug.Logger
	policyDirs    []string
	policyReaders []io.Reader
	parser        *parser.Parser
	regoScanner   *rego.Scanner
	skipRequired  bool
	regoOnly      bool
	loadEmbedded  bool
	options       []options.ScannerOption
	sync.Mutex
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbedded = b
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
	s.debug = debug.New(writer, "scan:cloudformation")
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetPolicyFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}

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
	s.parser = parser.New(options.ParserWithSkipRequiredCheck(s.skipRequired))
	return s
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(s.options...)
	if err := regoScanner.LoadPolicies(s.loadEmbedded, srcFS, s.policyDirs, s.policyReaders); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (results scan.Results, err error) {

	contexts, err := s.parser.ParseFS(ctx, fs, dir)
	if err != nil {
		return nil, err
	}

	if len(contexts) == 0 {
		return nil, nil
	}

	regoScanner, err := s.initRegoScanner(fs)
	if err != nil {
		return nil, err
	}

	for _, cfCtx := range contexts {
		if cfCtx == nil {
			continue
		}
		fileResults, err := s.scanFileContext(ctx, regoScanner, cfCtx, fs)
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

func (s *Scanner) ScanFile(ctx context.Context, fs fs.FS, path string) (scan.Results, error) {

	cfCtx, err := s.parser.ParseFile(ctx, fs, path)
	if err != nil {
		return nil, err
	}

	regoScanner, err := s.initRegoScanner(fs)
	if err != nil {
		return nil, err
	}

	results, err := s.scanFileContext(ctx, regoScanner, cfCtx, fs)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", fs)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}

func (s *Scanner) scanFileContext(ctx context.Context, regoScanner *rego.Scanner, cfCtx *parser.FileContext, fs fs.FS) (results scan.Results, err error) {
	state := adapter.Adapt(*cfCtx)
	if state == nil {
		return nil, nil
	}
	if !s.regoOnly {
		for _, rule := range rules.GetRegistered() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			if rule.Rule().RegoPackage != "" {
				continue
			}
			evalResult := rule.Evaluate(state)
			if len(evalResult) > 0 {
				s.debug.Log("Found %d results for %s", len(evalResult), rule.Rule().AVDID)
				for _, scanResult := range evalResult {
					if isIgnored(scanResult) {
						scanResult.OverrideStatus(scan.StatusIgnored)
					}

					ref := scanResult.Metadata().Reference()

					if ref == nil && scanResult.Metadata().Parent() != nil {
						ref = scanResult.Metadata().Parent().Reference()
					}

					reference := ref.(*parser.CFReference)
					description := getDescription(scanResult, reference)
					scanResult.OverrideDescription(description)
					results = append(results, scanResult)
				}
			}
		}
	}
	regoResults, err := regoScanner.ScanInput(ctx, rego.Input{
		Path:     cfCtx.Metadata().Range().GetFilename(),
		FS:       fs,
		Contents: state.ToRego(),
		Type:     types.SourceDefsec,
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}
	return append(results, regoResults...), nil
}

func getDescription(scanResult scan.Result, location *parser.CFReference) string {
	switch scanResult.Status() {
	case scan.StatusPassed:
		return fmt.Sprintf("Resource '%s' passed check: %s", location.LogicalID(), scanResult.Rule().Summary)
	case scan.StatusIgnored:
		return fmt.Sprintf("Resource '%s' had check ignored: %s", location.LogicalID(), scanResult.Rule().Summary)
	default:
		return scanResult.Description()
	}
}
