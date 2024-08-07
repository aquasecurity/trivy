package snapshot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	terraformScanner "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	tfparser "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
)

type Scanner struct {
	inner *terraformScanner.Scanner
}

func (s *Scanner) Name() string {
	return "Terraform Plan Snapshot"
}

func New(opts ...options.ScannerOption) *Scanner {
	scanner := &Scanner{
		inner: terraformScanner.New(opts...),
	}
	return scanner
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

		res, err := s.ScanFile(ctx, fsys, path)
		if errors.Is(err, errNoTerraformPlan) {
			return nil
		} else if err != nil {
			return err
		}
		results = append(results, res...)
		return nil
	}
	if err := fs.WalkDir(fsys, dir, walkFn); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Scanner) ScanFile(ctx context.Context, fsys fs.FS, filepath string) (scan.Results, error) {
	file, err := fsys.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return s.Scan(ctx, file)
}

func (s *Scanner) Scan(ctx context.Context, reader io.Reader) (scan.Results, error) {
	snap, err := parseSnapshot(reader)
	if err != nil {
		return nil, err
	}
	fsys, err := snap.toFS()
	if err != nil {
		return nil, fmt.Errorf("failed to convert snapshot to FS: %w", err)
	}

	s.inner.AddParserOptions(
		tfparser.OptionsWithTfVars(snap.inputVariables),
	)
	return s.inner.ScanFS(ctx, fsys, ".")
}
