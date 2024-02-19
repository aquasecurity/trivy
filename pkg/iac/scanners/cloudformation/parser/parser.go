package parser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	debug               debug.Logger
	skipRequired        bool
	parameterFiles      []string
	parameters          map[string]any
	overridedParameters Parameters
	configsFS           fs.FS
}

func WithParameters(params map[string]any) options.ParserOption {
	return func(cp options.ConfigurableParser) {
		if p, ok := cp.(*Parser); ok {
			p.parameters = params
		}
	}
}

func WithParameterFiles(files ...string) options.ParserOption {
	return func(cp options.ConfigurableParser) {
		if p, ok := cp.(*Parser); ok {
			p.parameterFiles = files
		}
	}
}

func WithConfigsFS(fsys fs.FS) options.ParserOption {
	return func(cp options.ConfigurableParser) {
		if p, ok := cp.(*Parser); ok {
			p.configsFS = fsys
		}
	}
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "cloudformation", "parser")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func New(opts ...options.ParserOption) *Parser {
	p := &Parser{}
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

		if !p.Required(fsys, path) {
			p.debug.Log("not a CloudFormation file, skipping %s", path)
			return nil
		}

		c, err := p.ParseFile(ctx, fsys, path)
		if err != nil {
			p.debug.Log("Error parsing file '%s': %s", path, err)
			return nil
		}
		contexts = append(contexts, c)
		return nil
	}); err != nil {
		return nil, err
	}
	return contexts, nil
}

func (p *Parser) Required(fsys fs.FS, path string) bool {
	if p.skipRequired {
		return true
	}

	f, err := fsys.Open(filepath.ToSlash(path))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if data, err := io.ReadAll(f); err == nil {
		return detection.IsType(path, bytes.NewReader(data), detection.FileTypeCloudFormation)
	}
	return false

}

func (p *Parser) ParseFile(ctx context.Context, fsys fs.FS, path string) (fctx *FileContext, err error) {
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
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		sourceFmt = JsonSourceFormat
	}

	f, err := fsys.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	fctx = &FileContext{
		filepath:     path,
		lines:        lines,
		SourceFormat: sourceFmt,
	}

	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := jfather.Unmarshal(content, fctx); err != nil {
			return nil, NewErrInvalidContent(path, err)
		}
	} else {
		if err := yaml.Unmarshal(content, fctx); err != nil {
			return nil, NewErrInvalidContent(path, err)
		}
	}

	fctx.OverrideParameters(p.overridedParameters)

	fctx.lines = lines
	fctx.SourceFormat = sourceFmt
	fctx.filepath = path

	p.debug.Log("Context loaded from source %s", path)

	// the context must be set to conditions before resources
	for _, c := range fctx.Conditions {
		c.setContext(fctx)
	}

	for name, r := range fctx.Resources {
		r.ConfigureResource(name, fsys, path, fctx)
	}

	return fctx, nil
}

func (p *Parser) parseParams() error {
	if p.overridedParameters != nil { // parameters have already been parsed
		return nil
	}

	params := make(Parameters)

	var errs []error

	for _, path := range p.parameterFiles {
		if parameters, err := p.parseParametersFile(path); err != nil {
			errs = append(errs, err)
		} else {
			params.Merge(parameters)
		}
	}

	if len(errs) != 0 {
		return errors.Join(errs...)
	}

	params.Merge(p.parameters)

	p.overridedParameters = params
	return nil
}

func (p *Parser) parseParametersFile(path string) (Parameters, error) {
	f, err := p.configsFS.Open(path)
	if err != nil {
		return nil, fmt.Errorf("parameters file %q open error: %w", path, err)
	}

	var parameters Parameters
	if err := json.NewDecoder(f).Decode(&parameters); err != nil {
		return nil, err
	}
	return parameters, nil
}
