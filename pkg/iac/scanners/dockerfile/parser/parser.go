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
			return nil, fmt.Errorf("parse dockerfile instruction: %w", err)
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

		// processing statement with sub-statement
		// example: ONBUILD RUN foo bar
		// https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/reference.md#onbuild
		if child.Next != nil && len(child.Next.Children) > 0 {
			cmd.SubCmd = child.Next.Children[0].Value
			child = child.Next.Children[0]
		}

		// mark if the instruction is in exec form
		// https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/reference.md#exec-form
		cmd.JSON = child.Attributes["json"]

		// heredoc may contain a script that will be executed in the shell, so we need to process it
		// https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/reference.md#here-documents
		if len(child.Heredocs) > 0 && child.Next != nil {
			cmd.Original = originalFromHeredoc(child)
			cmd.Value = []string{processHeredoc(child)}
		} else {
			for n := child.Next; n != nil; n = n.Next {
				cmd.Value = append(cmd.Value, n.Value)
			}
		}

		stage.Commands = append(stage.Commands, cmd)

	}
	if len(stage.Commands) > 0 {
		parsedFile.Stages = append(parsedFile.Stages, stage)
	}

	return &parsedFile, nil
}

func originalFromHeredoc(node *parser.Node) string {
	var sb strings.Builder
	sb.WriteString(node.Original)
	sb.WriteRune('\n')
	for i, heredoc := range node.Heredocs {
		sb.WriteString(heredoc.Content)
		sb.WriteString(heredoc.Name)
		if i != len(node.Heredocs)-1 {
			sb.WriteRune('\n')
		}
	}

	return sb.String()
}

// heredoc processing taken from here
// https://github.com/moby/buildkit/blob/9a39e2c112b7c98353c27e64602bc08f31fe356e/frontend/dockerfile/dockerfile2llb/convert.go#L1200
func processHeredoc(node *parser.Node) string {
	if parser.MustParseHeredoc(node.Next.Value) == nil || strings.HasPrefix(node.Heredocs[0].Content, "#!") {
		// more complex heredoc is passed to the shell as is
		var sb strings.Builder
		sb.WriteString(node.Next.Value)
		for _, heredoc := range node.Heredocs {
			sb.WriteRune('\n')
			sb.WriteString(heredoc.Content)
			sb.WriteString(heredoc.Name)
		}
		return sb.String()
	}

	// simple heredoc and the content is run in a shell
	content := node.Heredocs[0].Content
	if node.Heredocs[0].Chomp {
		content = parser.ChompHeredocContent(content)
	}

	content = strings.ReplaceAll(content, "\r\n", "\n")
	cmds := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	return strings.Join(cmds, " ; ")
}
