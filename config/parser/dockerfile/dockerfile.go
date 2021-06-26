package dockerfile

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"golang.org/x/xerrors"
)

// Parser is a Dockerfile parser
type Parser struct{}

// Resource holds a list of stages
type Resource struct {
	Stages map[string][]Command `json:"stages"`
}

// Command is the struct for each dockerfile command
type Command struct {
	Cmd       string
	SubCmd    string
	Flags     []string
	Value     []string
	Original  string
	StartLine int
	EndLine   int
	JSON      bool
	Stage     int
}

// Parse parses Dockerfile
func (p *Parser) Parse(contents []byte) (interface{}, error) {
	r := bytes.NewReader(contents)
	parsed, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("dockerfile parse error: %w", err)
	}

	fromValue := "args"
	from := make(map[string][]Command)

	var stages []*instructions.Stage
	for _, child := range parsed.AST.Children {
		instr, err := instructions.ParseInstruction(child)
		if err != nil {
			return nil, xerrors.Errorf("process dockerfile instructions: %w", err)
		}

		stage, ok := instr.(*instructions.Stage)
		if ok {
			stages = append(stages, stage)
		}

		if child.Value == "from" {
			fromValue = strings.TrimPrefix(child.Original, "FROM ")
		}

		cmd := Command{
			Cmd:       child.Value,
			Original:  child.Original,
			Flags:     child.Flags,
			StartLine: child.StartLine,
			EndLine:   child.EndLine,
			Stage:     currentStage(stages),
		}

		if child.Next != nil && len(child.Next.Children) > 0 {
			cmd.SubCmd = child.Next.Children[0].Value
			child = child.Next.Children[0]
		}

		cmd.JSON = child.Attributes["json"]
		for n := child.Next; n != nil; n = n.Next {
			cmd.Value = append(cmd.Value, n.Value)
		}

		from[fromValue] = append(from[fromValue], cmd)
	}

	var resource Resource
	resource.Stages = from

	j, err := json.Marshal(resource)
	if err != nil {
		return nil, xerrors.Errorf("json marshal error: %w", err)
	}

	var res interface{}
	if err = json.Unmarshal(j, &res); err != nil {
		return nil, xerrors.Errorf("json unmarshal error: %w", err)
	}

	return res, nil
}

// Return the index of the stages. If no stages are present,
// we set the index to zero.
func currentStage(stages []*instructions.Stage) int {
	if len(stages) == 0 {
		return 0
	}

	return len(stages) - 1
}
