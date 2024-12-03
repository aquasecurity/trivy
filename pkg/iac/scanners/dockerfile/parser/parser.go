package parser

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"

	"github.com/aquasecurity/trivy/pkg/iac/providers/dockerfile"
)

func Parse(_ context.Context, r io.Reader, path string) (any, error) {
	parsed, err := parser.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("dockerfile parse error: %w", err)
	}

	var (
		parsedFile dockerfile.Dockerfile
		stage      dockerfile.Stage
		stageIndex int
	)

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
