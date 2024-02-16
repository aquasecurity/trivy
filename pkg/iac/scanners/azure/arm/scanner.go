package arm

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm"
	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct { // nolint: gocritic
	scannerOptions        []options.ScannerOption
	parserOptions         []options.ParserOption
	debug                 debug.Logger
	frameworks            []framework.Framework
	skipRequired          bool
	regoOnly              bool
	loadEmbeddedPolicies  bool
	loadEmbeddedLibraries bool
	policyDirs            []string
	policyReaders         []io.Reader
	regoScanner           *rego.Scanner
	spec                  string
	sync.Mutex
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) SetRegoOnly(regoOnly bool) {
	s.regoOnly = regoOnly
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		scannerOptions: opts,
	}
	for _, opt := range opts {
		opt(scanner)
	}
	return scanner
}

func (s *Scanner) Name() string {
	return "Azure ARM"
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "azure", "arm")
	s.parserOptions = append(s.parserOptions, options.ParserWithDebug(writer))
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetSkipRequiredCheck(skipRequired bool) {
	s.skipRequired = skipRequired
}
func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetPolicyFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}
func (s *Scanner) SetDataFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbeddedPolicies = b
}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	s.loadEmbeddedLibraries = b
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetTraceWriter(io.Writer)        {}
func (s *Scanner) SetPerResultTracingEnabled(bool) {}
func (s *Scanner) SetDataDirs(...string)           {}
func (s *Scanner) SetPolicyNamespaces(...string)   {}
func (s *Scanner) SetRegoErrorLimit(_ int)         {}

func (s *Scanner) initRegoScanner(srcFS fs.FS) error {
	s.Lock()
	defer s.Unlock()
	if s.regoScanner != nil {
		return nil
	}
	regoScanner := rego.NewScanner(types.SourceCloud, s.scannerOptions...)
	regoScanner.SetParentDebugLogger(s.debug)
	if err := regoScanner.LoadPolicies(s.loadEmbeddedLibraries, s.loadEmbeddedPolicies, srcFS, s.policyDirs, s.policyReaders); err != nil {
		return err
	}
	s.regoScanner = regoScanner
	return nil
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	p := parser.New(fsys, s.parserOptions...)
	deployments, err := p.ParseFS(ctx, dir)
	if err != nil {
		return nil, err
	}
	if err := s.initRegoScanner(fsys); err != nil {
		return nil, err
	}

	return s.scanDeployments(ctx, deployments, fsys)
}

func (s *Scanner) scanDeployments(ctx context.Context, deployments []azure.Deployment, f fs.FS) (scan.Results, error) {

	var results scan.Results

	for _, deployment := range deployments {

		result, err := s.scanDeployment(ctx, deployment, f)
		if err != nil {
			return nil, err
		}
		results = append(results, result...)
	}

	return results, nil
}

func (s *Scanner) scanDeployment(ctx context.Context, deployment azure.Deployment, fsys fs.FS) (scan.Results, error) {
	var results scan.Results
	deploymentState := s.adaptDeployment(ctx, deployment)
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
			ruleResults := rule.Evaluate(deploymentState)
			s.debug.Log("Found %d results for %s", len(ruleResults), rule.GetRule().AVDID)
			if len(ruleResults) > 0 {
				results = append(results, ruleResults...)
			}
		}
	}

	regoResults, err := s.regoScanner.ScanInput(ctx, rego.Input{
		Path:     deployment.Metadata.Range().GetFilename(),
		FS:       fsys,
		Contents: deploymentState.ToRego(),
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan error: %w", err)
	}

	return append(results, regoResults...), nil
}

func (s *Scanner) adaptDeployment(ctx context.Context, deployment azure.Deployment) *state.State {
	return arm.Adapt(ctx, deployment)
}
