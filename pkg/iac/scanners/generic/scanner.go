package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func NewJsonScanner(opts ...options.ScannerOption) *GenericScanner {
	return NewScanner("JSON", types.SourceJSON, ParseFunc(parseJson), opts...)
}

func NewYamlScanner(opts ...options.ScannerOption) *GenericScanner {
	return NewScanner("YAML", types.SourceYAML, ParseFunc(parseYaml), opts...)
}

func NewTomlScanner(opts ...options.ScannerOption) *GenericScanner {
	return NewScanner("TOML", types.SourceTOML, ParseFunc(parseTOML), opts...)
}

type configParser interface {
	Parse(ctx context.Context, r io.Reader, path string) (any, error)
}

// GenericScanner is a scanner that scans a file as is without processing it
type GenericScanner struct {
	mu          sync.Mutex
	name        string
	source      types.Source
	logger      *log.Logger
	options     []options.ScannerOption
	regoScanner *rego.Scanner

	parser configParser
}

type ParseFunc func(ctx context.Context, r io.Reader, path string) (any, error)

func (f ParseFunc) Parse(ctx context.Context, r io.Reader, path string) (any, error) {
	return f(ctx, r, path)
}

func NewScanner(name string, source types.Source, parser configParser, opts ...options.ScannerOption) *GenericScanner {
	s := &GenericScanner{
		name:    name,
		options: opts,
		source:  source,
		logger:  log.WithPrefix(fmt.Sprintf("%s scanner", source)),
		parser:  parser,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *GenericScanner) Name() string {
	return s.name
}

func (s *GenericScanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	fileset, err := s.parseFS(ctx, fsys, dir)
	if err != nil {
		return nil, err
	}

	if len(fileset) == 0 {
		return nil, nil
	}

	var inputs []rego.Input
	for path, val := range fileset {
		switch v := val.(type) {
		case interface{ ToRego() any }:
			inputs = append(inputs, rego.Input{
				Path:     path,
				Contents: v.ToRego(),
				FS:       fsys,
			})
		case []any:
			for _, file := range v {
				inputs = append(inputs, rego.Input{
					Path:     path,
					Contents: file,
					FS:       fsys,
				})
			}
		default:
			inputs = append(inputs, rego.Input{
				Path:     path,
				Contents: v,
				FS:       fsys,
			})
		}
	}

	regoScanner, err := s.initRegoScanner(fsys)
	if err != nil {
		return nil, err
	}

	s.logger.Debug("Scanning files...", log.Int("count", len(inputs)))
	results, err := regoScanner.ScanInput(ctx, inputs...)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", fsys, false)
	return results, nil
}

func (s *GenericScanner) parseFS(ctx context.Context, fsys fs.FS, path string) (map[string]any, error) {
	files := make(map[string]any)
	if err := fs.WalkDir(fsys, filepath.ToSlash(path), func(path string, entry fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		f, err := fsys.Open(filepath.ToSlash(path))
		if err != nil {
			return err
		}
		defer f.Close()

		df, err := s.parser.Parse(ctx, f, path)
		if err != nil {
			s.logger.Error("Failed to parse file", log.FilePath(path), log.Err(err))
			return nil
		}
		files[path] = df
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

func (s *GenericScanner) initRegoScanner(srcFS fs.FS) (*rego.Scanner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.regoScanner != nil {
		return s.regoScanner, nil
	}
	regoScanner := rego.NewScanner(s.source, s.options...)
	if err := regoScanner.LoadPolicies(srcFS); err != nil {
		return nil, err
	}
	s.regoScanner = regoScanner
	return regoScanner, nil
}

func parseJson(ctx context.Context, r io.Reader, _ string) (any, error) {
	var target any
	if err := json.NewDecoder(r).Decode(&target); err != nil {
		return nil, err
	}
	return target, nil
}

func parseYaml(ctx context.Context, r io.Reader, _ string) (any, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var results []any

	marker := "\n---\n"
	altMarker := "\r\n---\r\n"
	if bytes.Contains(contents, []byte(altMarker)) {
		marker = altMarker
	}

	for _, partial := range strings.Split(string(contents), marker) {
		var target any
		if err := yaml.Unmarshal([]byte(partial), &target); err != nil {
			return nil, err
		}
		results = append(results, target)
	}

	return results, nil
}

func parseTOML(ctx context.Context, r io.Reader, _ string) (any, error) {
	var target any
	if _, err := toml.NewDecoder(r).Decode(&target); err != nil {
		return nil, err
	}
	return target, nil
}
