package kubernetes

import (
	"context"
	"io/fs"
	"sort"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ scanners.FSScanner = (*Scanner)(nil)
var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	mu          sync.Mutex
	logger      *log.Logger
	options     []options.ScannerOption
	regoScanner *rego.Scanner
	parser      *parser.Parser
}

func (s *Scanner) SetIncludeDeprecatedChecks(bool)                {}
func (s *Scanner) SetRegoOnly(bool)                               {}
func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {}

func NewScanner(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		options: opts,
		logger:  log.WithPrefix("k8s scanner"),
		parser:  parser.New(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Name() string {
	return "Kubernetes"
}

func (s *Scanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(types.SourceKubernetes, s.options...)
	if err := regoScanner.LoadPolicies(srcFS); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, dir string) (scan.Results, error) {

	k8sFilesets, err := s.parser.ParseFS(ctx, target, dir)
	if err != nil {
		return nil, err
	}

	if len(k8sFilesets) == 0 {
		return nil, nil
	}

	var inputs []rego.Input
	for path, k8sFiles := range k8sFilesets {
		for _, content := range k8sFiles {
			inputs = append(inputs, rego.Input{
				Path:     path,
				FS:       target,
				Contents: content,
			})
		}
	}

	regoScanner, err := s.initRegoScanner(target)
	if err != nil {
		return nil, err
	}

	s.logger.Debug("Scanning files", log.Int("count", len(inputs)))
	results, err := regoScanner.ScanInput(ctx, inputs...)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", target, false)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Rule().AVDID < results[j].Rule().AVDID
	})
	return results, nil
}
