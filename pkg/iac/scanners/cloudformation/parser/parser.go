package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/ignore"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Parser struct {
	logger              *log.Logger
	parameterFiles      []string
	parameters          map[string]any
	overridedParameters Parameters
	configsFS           fs.FS
}

type Option func(*Parser)

func WithParameters(params map[string]any) Option {
	return func(p *Parser) {
		p.parameters = params
	}
}

func WithParameterFiles(files ...string) Option {
	return func(p *Parser) {
		p.parameterFiles = files
	}
}

func WithConfigsFS(fsys fs.FS) Option {
	return func(p *Parser) {
		p.configsFS = fsys
	}
}

func New(opts ...Option) *Parser {
	p := &Parser{
		logger: log.WithPrefix("cloudformation parser"),
	}
	for _, option := range opts {
		option(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, fsys fs.FS, dir string) (FileContexts, error) {
	var contexts FileContexts
	if err := fs.WalkDir(fsys, filepath.ToSlash(dir), func(path string, entry fs.DirEntry, err error) error {
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

		c, err := p.ParseFile(ctx, fsys, path)
		if err != nil {
			p.logger.Error("Error parsing file", log.FilePath(path), log.Err(err))
			return nil
		}
		contexts = append(contexts, c)
		return nil
	}); err != nil {
		return nil, err
	}
	return contexts, nil
}

func (p *Parser) ParseFile(ctx context.Context, fsys fs.FS, filePath string) (fctx *FileContext, err error) {
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

	if p.configsFS == nil {
		p.configsFS = fsys
	}

	if err := p.parseParams(); err != nil {
		return nil, fmt.Errorf("failed to parse parameters file: %w", err)
	}

	sourceFmt := YamlSourceFormat
	if path.Ext(filePath) == ".json" {
		sourceFmt = JsonSourceFormat
	}

	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	fctx = &FileContext{
		filepath:     filePath,
		lines:        lines,
		SourceFormat: sourceFmt,
	}

	switch sourceFmt {
	case YamlSourceFormat:
		if err := yaml.Unmarshal(content, fctx); err != nil {
			return nil, NewErrInvalidContent(filePath, err)
		}
		fctx.Ignores = ignore.Parse(string(content), filePath, "")
	case JsonSourceFormat:
		if err := jfather.Unmarshal(content, fctx); err != nil {
			return nil, NewErrInvalidContent(filePath, err)
		}
	}

	fctx.stripNullProperties()

	fctx.overrideParameters(p.overridedParameters)

	if params := fctx.missingParameterValues(); len(params) > 0 {
		p.logger.Warn("Missing parameter values", log.FilePath(filePath), log.String("parameters", strings.Join(params, ", ")))
	}

	fctx.lines = lines
	fctx.SourceFormat = sourceFmt
	fctx.filepath = filePath

	p.logger.Debug("Context loaded from source", log.FilePath(filePath))

	// the context must be set to conditions before resources
	for _, c := range fctx.Conditions {
		c.setContext(fctx)
	}

	for name, r := range fctx.Resources {
		r.configureResource(name, fsys, filePath, fctx)
	}

	return fctx, nil
}

func (p *Parser) parseParams() error {
	if p.overridedParameters != nil { // parameters have already been parsed
		return nil
	}

	params := make(Parameters)

	var errs error
	for _, path := range p.parameterFiles {
		if parameters, err := p.parseParametersFile(path); err != nil {
			errs = multierror.Append(errs, err)
		} else {
			params.Merge(parameters)
		}
	}

	if errs != nil {
		return errs
	}

	params.Merge(p.parameters)

	p.overridedParameters = params
	return nil
}

func (p *Parser) parseParametersFile(filePath string) (Parameters, error) {
	f, err := p.configsFS.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("parameters file %q open error: %w", filePath, err)
	}

	var parameters Parameters
	if err := json.NewDecoder(f).Decode(&parameters); err != nil {
		return nil, err
	}
	return parameters, nil
}
