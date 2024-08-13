package parser

import (
	"context"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/log"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	logger *log.Logger
}

// New creates a new parser
func New(opts ...options.ParserOption) *Parser {
	p := &Parser{
		logger: log.WithPrefix("toml parser"),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) (map[string]any, error) {

	files := make(map[string]any)
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

// ParseFile parses toml content from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fsys fs.FS, path string) (any, error) {
	f, err := fsys.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var target any
	if _, err := toml.NewDecoder(f).Decode(&target); err != nil {
		return nil, err
	}
	return target, nil
}
