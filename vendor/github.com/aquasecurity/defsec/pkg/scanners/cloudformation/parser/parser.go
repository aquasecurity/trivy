package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/internal/debug"
	"github.com/aquasecurity/defsec/pkg/detection"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	debug        debug.Logger
	skipRequired bool
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "parse:cloudformation")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func New(options ...options.ParserOption) *Parser {
	p := &Parser{}
	for _, option := range options {
		option(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, dir string) (FileContexts, error) {
	var contexts FileContexts
	if err := fs.WalkDir(target, filepath.ToSlash(dir), func(path string, entry fs.DirEntry, err error) error {
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

		if !p.Required(target, path) {
			p.debug.Log("not a CloudFormation file, skipping %s", path)
			return nil
		}

		c, err := p.ParseFile(ctx, target, path)
		if err != nil {
			return err
		}
		contexts = append(contexts, c)
		return nil
	}); err != nil {
		return nil, err
	}
	return contexts, nil
}

func (p *Parser) Required(fs fs.FS, path string) bool {
	if p.skipRequired {
		return true
	}

	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	return detection.IsType(path, f, detection.FileTypeCloudFormation)
}

func (p *Parser) ParseFile(ctx context.Context, fs fs.FS, path string) (context *FileContext, err error) {

	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic during parse: %s", e)
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	sourceFmt := YamlSourceFormat
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		sourceFmt = JsonSourceFormat
	}

	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	content, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	context = &FileContext{
		filepath:     path,
		lines:        lines,
		SourceFormat: sourceFmt,
	}

	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := jfather.Unmarshal(content, context); err != nil {
			return nil, NewErrInvalidContent(path, err)
		}
	} else {
		if err := yaml.Unmarshal(content, context); err != nil {
			return nil, NewErrInvalidContent(path, err)
		}
	}

	context.lines = lines
	context.SourceFormat = sourceFmt
	context.filepath = path

	p.debug.Log("Context loaded from source %s", path)

	for name, r := range context.Resources {
		r.ConfigureResource(name, fs, path, context)
	}

	return context, nil
}
