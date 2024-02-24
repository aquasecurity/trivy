package ansible

import (
	"context"
	"fmt"
	"io/fs"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/ansible"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var (
	_ scanners.FSScanner = (*Scanner)(nil)
)

type Scanner struct {
	*rego.RegoScannerProvider
	opts []options.ScannerOption
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		RegoScannerProvider: rego.NewRegoScannerProvider(opts...),
		opts:                opts,
	}
	for _, opt := range opts {
		opt(scanner)
	}
	return scanner
}

func (s *Scanner) Name() string {
	return "Ansible"
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	projects, err := parser.ParseProjects(fsys, dir)
	if err != nil {
		return nil, err
	}

	var results scan.Results

	for _, proj := range projects {
		res, err := s.scanProject(ctx, fsys, proj)
		if err != nil {
			return nil, err
		}
		results = append(results, res...)
	}

	return results, nil
}

func (s *Scanner) scanProject(ctx context.Context, fsys fs.FS, project *parser.AnsibleProject) (scan.Results, error) {
	tasks := project.ListTasks()
	state := adapter.Adapt(tasks)

	var results scan.Results

	rs, err := s.InitRegoScanner(fsys, s.opts)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	regoResults, err := rs.ScanInput(ctx, types.SourceCloud, rego.Input{
		Path:     project.Path(),
		FS:       fsys,
		Contents: state.ToRego(),
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan: %w", err)
	}

	return append(results, regoResults...), nil
}
