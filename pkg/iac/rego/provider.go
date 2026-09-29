package rego

import (
	"fmt"
	"io/fs"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func WithRegoScanner(rs *Scanner) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if ss, ok := s.(*RegoScannerProvider); ok {
			ss.regoScanner = rs
		}
	}
}

type RegoScannerProvider struct {
	mu          sync.Mutex
	regoScanner *Scanner
}

func NewRegoScannerProvider(opts ...options.ScannerOption) *RegoScannerProvider {
	s := &RegoScannerProvider{}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *RegoScannerProvider) InitRegoScanner(fsys fs.FS, opts []options.ScannerOption) (*Scanner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	s.regoScanner = NewScanner(opts...)
	if err := s.regoScanner.LoadPolicies(fsys); err != nil {
		return nil, fmt.Errorf("load checks: %w", err)
	}
	return s.regoScanner, nil
}
