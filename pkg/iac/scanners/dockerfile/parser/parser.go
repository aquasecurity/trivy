package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"

	"github.com/aquasecurity/trivy/pkg/iac/debug"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/providers/dockerfile"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	debug        debug.Logger
	skipRequired bool
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "dockerfile", "parser")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

// New creates a new Dockerfile parser
func New(opts ...options.ParserOption) *Parser {
	p := &Parser{}
	for _, option := range opts {
		option(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) (map[string]*dockerfile.Dockerfile, error) {

	files := make(map[string]*dockerfile.Dockerfile)
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
			// TODO add debug for parse errors
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
func (p *Parser) ParseFile(_ context.Context, fsys fs.FS, path string) (*dockerfile.Dockerfile, error) {
	f, err := fsys.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return p.parse(path, f)
}

func (p *Parser) Required(path string) bool {
	if p.skipRequired {
		return true
	}
	return detection.IsType(path, nil, detection.FileTypeDockerfile)
}

func (p *Parser) parse(path string, r io.Reader) (*dockerfile.Dockerfile, error) {
	parsed, err := parser.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("dockerfile parse error: %w", err)
	}

	var parsedFile dockerfile.Dockerfile
	var stage dockerfile.Stage
	var stageIndex int
	fromValue := "args"
	for _, child := range parsed.AST.Children {
		child.Value = strings.ToLower(child.Value)

		instr, err := instructions.ParseInstruction(child)
		if err != nil {
			return nil, fmt.Errorf("process dockerfile instructions: %w", err)
		}

		if _, ok := instr.(*instructions.Stage); ok {
			if len(stage.Commands) > 0 {
				parsedFile.Stages = append(parsedFile.Stages, stage)
			}
			if fromValue != "args" {
				stageIndex++
			}
			fromValue = strings.TrimSpace(strings.TrimPrefix(child.Original, "FROM "))
			stage = dockerfile.Stage{
				Name: fromValue,
			}
		}

		cmd := dockerfile.Command{
			Cmd:       child.Value,
			Original:  child.Original,
			Flags:     child.Flags,
			Stage:     stageIndex,
			Path:      path,
			StartLine: child.StartLine,
			EndLine:   child.EndLine,
		}

		if child.Next != nil && len(child.Next.Children) > 0 {
			cmd.SubCmd = child.Next.Children[0].Value
			child = child.Next.Children[0]
		}

		cmd.JSON = child.Attributes["json"]
		for n := child.Next; n != nil; n = n.Next {
			cmd.Value = append(cmd.Value, n.Value)
		}

		stage.Commands = append(stage.Commands, cmd)

	}
	if len(stage.Commands) > 0 {
		parsedFile.Stages = append(parsedFile.Stages, stage)
	}

	return &parsedFile, nil
}
