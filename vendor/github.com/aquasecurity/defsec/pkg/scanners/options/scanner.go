package options

import (
	"io"
	"io/fs"
)

type ConfigurableScanner interface {
	SetDebugWriter(io.Writer)
	SetTraceWriter(io.Writer)
	SetPerResultTracingEnabled(bool)
	SetPolicyDirs(...string)
	SetDataDirs(...string)
	SetPolicyNamespaces(...string)
	SetSkipRequiredCheck(bool)
	SetPolicyReaders([]io.Reader)
	SetPolicyFilesystem(fs.FS)
	SetUseEmbeddedPolicies(bool)
}

type ScannerOption func(s ConfigurableScanner)

func OptionWithPolicyReaders(readers ...io.Reader) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyReaders(readers)
	}
}

// ScannerWithDebug specifies an io.Writer for debug logs - if not set, they are discarded
func ScannerWithDebug(w io.Writer) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetDebugWriter(w)
	}
}

func ScannerWithEmbeddedPolicies(embedded bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetUseEmbeddedPolicies(embedded)
	}
}

// ScannerWithTrace specifies an io.Writer for trace logs (mainly rego tracing) - if not set, they are discarded
func ScannerWithTrace(w io.Writer) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetTraceWriter(w)
	}
}

func ScannerWithPerResultTracing(enabled bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPerResultTracingEnabled(enabled)
	}
}

func ScannerWithPolicyDirs(paths ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyDirs(paths...)
	}
}

func ScannerWithDataDirs(paths ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetDataDirs(paths...)
	}
}

// ScannerWithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func ScannerWithPolicyNamespaces(namespaces ...string) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyNamespaces(namespaces...)
	}
}

func ScannerWithSkipRequiredCheck(skip bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetSkipRequiredCheck(skip)
	}
}

func ScannerWithPolicyFilesystem(f fs.FS) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetPolicyFilesystem(f)
	}
}
