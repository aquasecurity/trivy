package rego

import (
	"context"
	"io"
	"io/fs"

	"github.com/open-policy-agent/opa/ast"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

var checkTypesWithSubtype = set.New[types.Source](types.SourceCloud, types.SourceDefsec, types.SourceKubernetes)

var supportedProviders = makeSupportedProviders()

func makeSupportedProviders() set.Set[string] {
	m := set.New[string]()
	for _, p := range providers.AllProviders() {
		m.Append(string(p))
	}
	m.Append("kind") // kubernetes
	return m
}

var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	namespaces               set.Set[string]
	runtimeValues            *ast.Term
	regoErrorLimit           int
	logger                   *log.Logger
	traceWriter              io.Writer
	tracePerResult           bool
	policyFS                 fs.FS
	policyDirs               []string
	policyReaders            []io.Reader
	dataFS                   fs.FS
	dataDirs                 []string
	frameworks               []framework.Framework
	includeDeprecatedChecks  bool
	includeEmbeddedPolicies  bool
	includeEmbeddedLibraries bool

	embeddedLibs   map[string]*ast.Module
	embeddedChecks map[string]*ast.Module
	customSchemas  map[string][]byte

	disabledCheckIDs set.Set[string]

	runners []*ChecksRunner
}

type DynamicMetadata struct {
	Warning   bool
	Filepath  string
	Message   string
	StartLine int
	EndLine   int
}

func NewScanner(opts ...options.ScannerOption) *Scanner {
	LoadAndRegister()

	s := &Scanner{
		logger:           log.WithPrefix("rego"),
		regoErrorLimit:   ast.CompileErrorLimitDefault,
		namespaces:       builtinNamespaces.Clone(),
		customSchemas:    make(map[string][]byte),
		disabledCheckIDs: set.New[string](),
	}

	for _, opt := range opts {
		opt(s)
	}
	return s
}

type Input struct {
	Path     string `json:"path"`
	FS       fs.FS  `json:"-"`
	Contents any    `json:"contents"`
}

func GetInputsContents(inputs []Input) []any {
	results := make([]any, len(inputs))
	for i, c := range inputs {
		results[i] = c.Contents
	}
	return results
}

func (s *Scanner) ScanInput(ctx context.Context, sourceType types.Source, inputs ...Input) (scan.Results, error) {
	s.logger.Debug("Scanning inputs", "count", len(inputs))
	if len(inputs) == 0 {
		return nil, nil
	}

	var collectedResults scan.Results
	for _, runner := range s.runners {
		results, err := runner.RunChecks(ctx, sourceType, inputs...)
		if err != nil {
			s.logger.Error("Failed to run checks", log.Err(err))
			continue
		}
		if results != nil {
			collectedResults = append(collectedResults, results...)
		}
	}

	return collectedResults, nil
}
