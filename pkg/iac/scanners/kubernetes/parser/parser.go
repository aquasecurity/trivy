package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	kyaml "sigs.k8s.io/yaml"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	debug debug.Logger
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "kubernetes", "parser")
}

// New creates a new K8s parser
func New(opts ...options.ParserOption) *Parser {
	p := &Parser{}
	for _, option := range opts {
		option(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) (map[string][]any, error) {
	files := make(map[string][]any)
	if err := fs.WalkDir(target, filepath.ToSlash(path), func(path string, entry fs.DirEntry, err error) error {
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

		parsed, err := p.ParseFile(ctx, target, path)
		if err != nil {
			p.debug.Log("Parse error in '%s': %s", path, err)
			return nil
		}

		files[path] = parsed
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// ParseFile parses Kubernetes manifest from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fsys fs.FS, path string) ([]any, error) {
	f, err := fsys.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return p.Parse(f, path)
}

func (p *Parser) Parse(r io.Reader, path string) ([]any, error) {

	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(contents) == 0 {
		return nil, nil
	}

	if strings.TrimSpace(string(contents))[0] == '{' {
		var target any
		if err := json.Unmarshal(contents, &target); err != nil {
			return nil, err
		}

		contents, err = kyaml.JSONToYAML(contents) // convert into yaml to reuse file parsing logic
		if err != nil {
			return nil, err
		}
	}

	var results []any

	re := regexp.MustCompile(`(?m:^---\r?\n)`)
	pos := 0
	for _, partial := range re.Split(string(contents), -1) {
		var result Manifest
		result.Path = path
		if err := yaml.Unmarshal([]byte(partial), &result); err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		if result.Content != nil {
			result.Content.Offset = pos
			results = append(results, result.ToRego())
		}
		pos += len(strings.Split(partial, "\n"))
	}

	return results, nil
}
