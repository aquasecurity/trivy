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

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func NewJsonScanner(opts ...options.ScannerOption) *GenericScanner[*identityMarshaler] {
	return NewScanner("JSON", types.SourceJSON, ParseFunc[*identityMarshaler](parseJson), opts...)
}

func NewYamlScanner(opts ...options.ScannerOption) *GenericScanner[*identityMarshaler] {
	return NewScanner("YAML", types.SourceYAML, ParseFunc[*identityMarshaler](parseYaml), opts...)
}

func NewTomlScanner(opts ...options.ScannerOption) *GenericScanner[*identityMarshaler] {
	return NewScanner("TOML", types.SourceTOML, ParseFunc[*identityMarshaler](parseTOML), opts...)
}

type LogicalPath struct {
	Val string
}

func (p LogicalPath) Valid() bool {
	return p.Val != ""
}

type LogicalPathFinder interface {
	ResolveLogicalPath(filename string, startLine, endLine int) LogicalPath
}

type RegoMarshaler interface {
	ToRego() any
}

type identityMarshaler struct {
	value any
}

func (r identityMarshaler) ToRego() any {
	return r.value
}

type configParser[T RegoMarshaler] interface {
	Parse(ctx context.Context, r io.Reader, path string) ([]T, error)
}

// GenericScanner is a scanner that scans a file as is without processing it
type GenericScanner[T RegoMarshaler] struct {
	*rego.RegoScannerProvider
	name    string
	source  types.Source
	logger  *log.Logger
	options []options.ScannerOption

	parser configParser[T]
}

type ParseFunc[T RegoMarshaler] func(ctx context.Context, r io.Reader, path string) ([]T, error)

func (f ParseFunc[T]) Parse(ctx context.Context, r io.Reader, path string) ([]T, error) {
	return f(ctx, r, path)
}

func NewScanner[T RegoMarshaler](
	name string,
	source types.Source,
	parser configParser[T],
	opts ...options.ScannerOption,
) *GenericScanner[T] {
	s := &GenericScanner[T]{
		RegoScannerProvider: rego.NewRegoScannerProvider(opts...),
		name:                name,
		options:             opts,
		source:              source,
		logger:              log.WithPrefix(fmt.Sprintf("%s scanner", source)),
		parser:              parser,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *GenericScanner[T]) Name() string {
	return s.name
}

func (s *GenericScanner[T]) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	fileset, err := s.parseFS(ctx, fsys, dir)
	if err != nil {
		return nil, err
	}

	if len(fileset) == 0 {
		return nil, nil
	}

	var inputs []rego.Input
	for filePath, parsedObjects := range fileset {
		for _, obj := range parsedObjects {
			inputs = append(inputs, rego.Input{
				Path:     filePath,
				Contents: obj.ToRego(),
				FS:       fsys,
			})
		}
	}

	rs, err := s.InitRegoScanner(fsys, s.options)
	if err != nil {
		return nil, fmt.Errorf("init rego scanner: %w", err)
	}

	s.logger.Debug("Scanning files...", log.Int("count", len(inputs)))
	results, err := rs.ScanInput(ctx, s.source, inputs...)
	if err != nil {
		return nil, err
	}
	results.SetSourceAndFilesystem("", fsys, false)

	if err := s.applyIgnoreRules(fsys, results); err != nil {
		return nil, err
	}

	// TODO: Move this to the rego package?
	for i, res := range results {
		if res.Status() != scan.StatusFailed {
			continue
		}

		srcPath := res.FilesystemPath()
		if parsedObjects, ok := fileset[srcPath]; ok {
			for _, obj := range parsedObjects {
				if f, ok := any(obj).(LogicalPathFinder); ok {
					logicalPath := f.ResolveLogicalPath(srcPath, res.Range().GetStartLine(), res.Range().GetEndLine())
					if logicalPath.Valid() {
						res.WithCausePath(logicalPath.Val)
						results[i] = res
						break
					}
				}
			}
		}
	}

	return results, nil
}

func (s *GenericScanner[T]) supportsIgnoreRules() bool {
	return s.source == types.SourceDockerfile
}

func (s *GenericScanner[T]) parseFS(ctx context.Context, fsys fs.FS, path string) (map[string][]T, error) {
	files := make(map[string][]T)
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

func (s *GenericScanner[T]) applyIgnoreRules(fsys fs.FS, results scan.Results) error {
	if !s.supportsIgnoreRules() {
		return nil
	}

	uniqueFiles := lo.Uniq(lo.Map(results.GetFailed(), func(res scan.Result, _ int) string {
		return res.Metadata().Range().GetFilename()
	}))

	for _, filename := range uniqueFiles {
		content, err := fs.ReadFile(fsys, filename)
		if err != nil {
			return err
		}

		ignoreRules := ignore.Parse(string(content), filename, "")
		results.Ignore(ignoreRules, nil)
	}
	return nil
}

func parseJson(_ context.Context, r io.Reader, _ string) ([]*identityMarshaler, error) {
	var target any
	if err := json.NewDecoder(r).Decode(&target); err != nil {
		return nil, err
	}
	return []*identityMarshaler{{value: target}}, nil
}

func parseYaml(_ context.Context, r io.Reader, _ string) ([]*identityMarshaler, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var documents []*identityMarshaler

	marker := "\n---\n"
	altMarker := "\r\n---\r\n"
	if bytes.Contains(contents, []byte(altMarker)) {
		marker = altMarker
	}

	for partial := range strings.SplitSeq(string(contents), marker) {
		var target any
		if err := yaml.Unmarshal([]byte(partial), &target); err != nil {
			return nil, err
		}
		documents = append(documents, &identityMarshaler{target})
	}

	return documents, nil
}

func parseTOML(_ context.Context, r io.Reader, _ string) ([]*identityMarshaler, error) {
	var target any
	if _, err := toml.NewDecoder(r).Decode(&target); err != nil {
		return nil, err
	}
	return []*identityMarshaler{{value: target}}, nil
}
