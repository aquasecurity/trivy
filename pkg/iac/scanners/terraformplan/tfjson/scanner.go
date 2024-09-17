package tfjson

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	terraformScanner "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/tfjson/parser"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Scanner struct {
	parser                  *parser.Parser
	logger                  *log.Logger
	options                 []options.ScannerOption
	spec                    string
	executorOpt             []executor.Option
	frameworks              []framework.Framework
	loadEmbeddedPolicies    bool
	loadEmbeddedLibraries   bool
	enableEmbeddedLibraries bool
	policyDirs              []string
	policyReaders           []io.Reader
}

func (s *Scanner) SetIncludeDeprecatedChecks(bool)    {}
func (s *Scanner) SetCustomSchemas(map[string][]byte) {}

func (s *Scanner) SetUseEmbeddedLibraries(b bool) {
	s.loadEmbeddedLibraries = b
}

func (s *Scanner) SetSpec(spec string) {
	s.spec = spec
}

func (s *Scanner) SetRegoOnly(regoOnly bool) {
	s.executorOpt = append(s.executorOpt, executor.OptionWithRegoOnly(regoOnly))
}

func (s *Scanner) SetFrameworks(frameworks []framework.Framework) {
	s.frameworks = frameworks
}

func (s *Scanner) SetUseEmbeddedPolicies(b bool) {
	s.loadEmbeddedPolicies = b
}

func (s *Scanner) SetEmbeddedLibrariesEnabled(enabled bool) {
	s.enableEmbeddedLibraries = enabled
}

func (s *Scanner) SetPolicyReaders(readers []io.Reader) {
	s.policyReaders = readers
}

func (s *Scanner) SetTraceWriter(_ io.Writer) {
}

func (s *Scanner) SetPerResultTracingEnabled(_ bool) {
}

func (s *Scanner) SetPolicyDirs(dirs ...string) {
	s.policyDirs = dirs
}

func (s *Scanner) SetDataDirs(_ ...string)         {}
func (s *Scanner) SetPolicyNamespaces(_ ...string) {}

func (s *Scanner) SetPolicyFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}

func (s *Scanner) SetDataFilesystem(_ fs.FS) {
	// handled by rego when option is passed on
}
func (s *Scanner) SetRegoErrorLimit(_ int) {}

func (s *Scanner) Name() string {
	return "Terraform Plan JSON"
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {

	var results scan.Results

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		res, err := s.ScanFile(path, fsys)
		if err != nil {
			return fmt.Errorf("failed to scan %s: %w", path, err)
		}

		results = append(results, res...)
		return nil
	}

	if err := fs.WalkDir(fsys, dir, walkFn); err != nil {
		return nil, err
	}

	return results, nil
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		options: opts,
		logger:  log.WithPrefix("tfjson scanner"),
		parser:  parser.New(),
	}
	for _, o := range opts {
		o(scanner)
	}

	return scanner
}

func (s *Scanner) ScanFile(filepath string, fsys fs.FS) (scan.Results, error) {

	s.logger.Debug("Scanning file", log.FilePath(filepath))
	file, err := fsys.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return s.Scan(file)
}

func (s *Scanner) Scan(reader io.Reader) (scan.Results, error) {

	planFile, err := s.parser.Parse(reader)
	if err != nil {
		return nil, err
	}

	planFS, err := planFile.ToFS()
	if err != nil {
		return nil, fmt.Errorf("failed to convert plan to FS: %w", err)
	}

	scanner := terraformScanner.New(s.options...)
	return scanner.ScanFS(context.TODO(), planFS, ".")
}
