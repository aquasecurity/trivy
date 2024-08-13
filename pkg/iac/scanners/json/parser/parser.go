package parser

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Parser struct {
	logger *log.Logger
}

// New creates a new parser
func New() *Parser {
	return &Parser{
		logger: log.WithPrefix("json parser"),
	}
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

// ParseFile parses Dockerfile content from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fsys fs.FS, path string) (any, error) {
	f, err := fsys.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var target any
	if err := json.NewDecoder(f).Decode(&target); err != nil {
		return nil, err
	}
	return target, nil
}
