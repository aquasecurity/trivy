package ansible

import (
	"context"
	"fmt"
	"io/fs"

	"gopkg.in/yaml.v3"

	adapter "github.com/aquasecurity/trivy/pkg/iac/adapters/ansible"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	_ scanners.FSScanner          = (*Scanner)(nil)
	_ options.ConfigurableScanner = (*Scanner)(nil)
)

type Scanner struct {
	*rego.RegoScannerProvider
	opts       []options.ScannerOption
	parserOpts []parser.Option
}

func WithPlaybooks(playbooks []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.parserOpts = append(ss.parserOpts, parser.WithPlaybooks(playbooks...))
		}
	}
}

func WithInventories(inventories []string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.parserOpts = append(ss.parserOpts, parser.WithInventories(inventories...))
		}
	}
}

func WithExtraVars(evars map[string]any) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.parserOpts = append(ss.parserOpts, parser.WithExtraVars(evars))
		}
	}
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
	roots, err := parser.FindProjects(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("find projects: %w", err)
	}

	var results scan.Results
	for _, projectRoot := range roots {
		log.WithPrefix("ansible").Debug("Detected ansible project", log.FilePath(projectRoot))
		project, err := parser.ParseProject(fsys, projectRoot, s.parserOpts...)
		if err != nil {
			return nil, fmt.Errorf("parse project: %w", err)
		}
		res, err := s.scanProject(ctx, fsys, project)
		if err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		results = append(results, res...)
	}
	return results, nil
}

func (s *Scanner) scanProject(ctx context.Context, fsys fs.FS, project *parser.AnsibleProject) (scan.Results, error) {
	tasks := project.ListTasks().FilterByState("absent")
	state := adapter.Adapt(tasks)

	rs, err := s.InitRegoScanner(fsys, s.opts)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	results, err := rs.ScanInput(ctx, types.SourceCloud, rego.Input{
		Path:     project.Path(),
		FS:       fsys,
		Contents: state.ToRego(),
	})
	if err != nil {
		return nil, fmt.Errorf("rego scan: %w", err)
	}

	for i, res := range results {
		if res.Status() != scan.StatusFailed {
			continue
		}

		rendered, ok := renderCause(tasks, res.Range())
		if ok {
			res.WithRenderedCause(rendered)
			results[i] = res
		}
	}

	return results, nil
}

func renderCause(tasks parser.ResolvedTasks, causeRng types.Range) (scan.RenderedCause, bool) {
	fields := fieldsForRange(tasks, causeRng)
	if fields == nil {
		return scan.RenderedCause{}, false
	}

	b, err := yaml.Marshal(fields)
	if err != nil {
		return scan.RenderedCause{}, false
	}
	return scan.RenderedCause{Raw: string(b)}, true
}

func fieldsForRange(tasks parser.ResolvedTasks, causeRng types.Range) any {
	for _, task := range tasks {
		taskRng := task.Metadata.Range()
		if taskRng.GetFilename() == causeRng.GetFilename() && taskRng.Includes(causeRng) {
			queryRange := parser.Range{
				Start: causeRng.GetStartLine(),
				End:   causeRng.GetEndLine(),
			}
			return task.GetFieldsByRange(queryRange)
		}
	}
	return nil
}
