package parser

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	logger       *log.Logger
	skipRequired bool
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

// New creates a new parser
func New(opts ...options.ParserOption) *Parser {
	p := &Parser{
		logger: log.WithPrefix("yaml parser"),
	}
	for _, opt := range opts {
		opt(p)
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
		if !p.Required(path) {
			return nil
		}
		df, err := p.ParseFile(ctx, target, path)
		if err != nil {
			p.logger.Error("Parse error", log.FilePath(path), log.Err(err))
			return nil
		}
		files[path] = df
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// ParseFile parses yaml content from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fsys fs.FS, path string) ([]any, error) {
	f, err := fsys.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	contents, err := io.ReadAll(f)
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

func (p *Parser) Required(path string) bool {
	if p.skipRequired {
		return true
	}
	return detection.IsType(path, nil, detection.FileTypeYAML)
}
