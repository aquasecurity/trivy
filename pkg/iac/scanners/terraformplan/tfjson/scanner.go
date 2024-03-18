package tfjson

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	terraformScanner "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/tfjson/parser"
)

var tfPlanExts = []string{
	"**/*tfplan.json",
	"**/*tf.json",
}

type Scanner struct {
	parser    parser.Parser
	parserOpt []options.ParserOption
	debug     debug.Logger

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

func (s *Scanner) SetSkipRequiredCheck(skip bool) {
	s.parserOpt = append(s.parserOpt, options.ParserWithSkipRequiredCheck(skip))
}

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.parserOpt = append(s.parserOpt, options.ParserWithDebug(writer))
	s.executorOpt = append(s.executorOpt, executor.OptionWithDebugWriter(writer))
	s.debug = debug.New(writer, "tfplan", "scanner")
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

func (s *Scanner) ScanFS(ctx context.Context, inputFS fs.FS, dir string) (scan.Results, error) {
	var filesFound []string

	for _, ext := range tfPlanExts {
		files, err := doublestar.Glob(inputFS, ext, doublestar.WithFilesOnly())
		if err != nil {
			return nil, fmt.Errorf("unable to scan for terraform plan files: %w", err)
		}
		filesFound = append(filesFound, files...)
	}

	var results scan.Results
	for _, f := range filesFound {
		res, err := s.ScanFile(f, inputFS)
		if err != nil {
			return nil, err
		}
		results = append(results, res...)
	}
	return results, nil
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		parser:  *parser.New(),
		options: opts,
	}
	for _, o := range opts {
		o(scanner)
	}
	return scanner
}

func (s *Scanner) ScanFile(filepath string, fsys fs.FS) (scan.Results, error) {

	s.debug.Log("Scanning file %s", filepath)
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
		return nil, err
	}

	scanner := terraformScanner.New(s.options...)
	return scanner.ScanFS(context.TODO(), planFS, ".")
}
