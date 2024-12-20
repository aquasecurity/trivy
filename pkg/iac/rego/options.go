package rego

import (
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func WithPolicyReader(readers ...io.Reader) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.policyReaders = readers
		}
	}
}

func WithEmbeddedPolicies(include bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.includeEmbeddedPolicies = include
		}
	}
}

func WithEmbeddedLibraries(include bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.includeEmbeddedLibraries = include
		}
	}
}

// WithTrace specifies an io.Writer for trace logs (mainly rego tracing) - if not set, they are discarded
func WithTrace(w io.Writer) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.traceWriter = w
		}
	}
}

func WithPerResultTracing(enabled bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.tracePerResult = enabled
		}
	}
}

func WithPolicyDirs(paths ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.policyDirs = paths
		}
	}
}

func WithDataDirs(paths ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.dataDirs = paths
		}
	}
}

// WithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func WithPolicyNamespaces(namespaces ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.ruleNamespaces.Append(namespaces...)
		}
	}
}

func WithPolicyFilesystem(fsys fs.FS) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.policyFS = fsys
		}
	}
}

func WithDataFilesystem(fsys fs.FS) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.dataFS = fsys
		}
	}
}

func WithRegoErrorLimits(limit int) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.regoErrorLimit = limit
		}
	}
}

func WithCustomSchemas(schemas map[string][]byte) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.customSchemas = schemas
		}
	}
}

// WithDisabledCheckIDs disables checks by their ID (ID field in metadata)
func WithDisabledCheckIDs(ids ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.disabledCheckIDs.Append(ids...)
		}
	}
}

func WithIncludeDeprecatedChecks(enabled bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.includeDeprecatedChecks = true
		}
	}
}

func WithFrameworks(frameworks ...framework.Framework) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*Scanner); ok {
			ss.frameworks = frameworks
		}
	}
}
