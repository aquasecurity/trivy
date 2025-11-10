package config

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
	"k8s.io/utils/strings/slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

var (
	_ analyzer.PostAnalyzer = (*Analyzer)(nil)

	requiredExts = []string{".json", ".yaml", ".yml", ".tfvars"}
)

// Analyzer represents an analyzer for config files,
// which is embedded into each config analyzer such as Kubernetes.
type Analyzer struct {
	typ     analyzer.Type
	version int
	scanner *misconf.Scanner
}

func NewAnalyzer(t analyzer.Type, version int, fileType detection.FileType, opts analyzer.AnalyzerOptions) (*Analyzer, error) {
	s, err := misconf.NewScanner(fileType, opts.MisconfScannerOption)
	if err != nil {
		return nil, xerrors.Errorf("%s scanner init error: %w", t, err)
	}
	return &Analyzer{
		typ:     t,
		version: version,
		scanner: s,
	}, nil
}

// PostAnalyze performs configuration analysis on the input filesystem and detect misconfigurations.
func (a *Analyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	misconfs, err := a.scanner.Scan(ctx, input.FS)
	if err != nil {
		return nil, xerrors.Errorf("%s scan error: %w", a.typ, err)
	}
	return &analyzer.AnalysisResult{Misconfigurations: misconfs}, nil
}

// Required checks if the given file path has one of the required file extensions.
func (a *Analyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredExts, filepath.Ext(filePath))
}

// Type returns the analyzer type of the current Analyzer instance.
func (a *Analyzer) Type() analyzer.Type {
	return a.typ
}

// Version returns the version of the current Analyzer instance.
func (a *Analyzer) Version() int {
	return a.version
}
