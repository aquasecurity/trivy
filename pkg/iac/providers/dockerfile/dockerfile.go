package dockerfile

import (
	"reflect"

	"github.com/aquasecurity/trivy/pkg/iac/rego/convert"
)

// NOTE: we are currently preserving mixed case json here for backward compatibility

// Dockerfile represents a parsed Dockerfile
type Dockerfile struct {
	Stages []Stage
}

type Stage struct {
	Name     string
	Commands []Command
}

func (d Dockerfile) ToRego() any {
	return map[string]any{
		"Stages": convert.SliceToRego(reflect.ValueOf(d.Stages)),
	}
}

func (s Stage) ToRego() any {
	return map[string]any{
		"Name":     s.Name,
		"Commands": convert.SliceToRego(reflect.ValueOf(s.Commands)),
	}
}

// Command is the struct for each dockerfile command
type Command struct {
	Cmd       string
	SubCmd    string
	Flags     []string
	Value     []string
	Original  string
	JSON      bool
	Stage     int
	Path      string
	StartLine int
	EndLine   int
}

func (c Command) ToRego() any {
	return map[string]any{
		"Cmd":       c.Cmd,
		"SubCmd":    c.SubCmd,
		"Flags":     c.Flags,
		"Value":     c.Value,
		"Original":  c.Original,
		"JSON":      c.JSON,
		"Stage":     c.Stage,
		"Path":      c.Path,
		"StartLine": c.StartLine,
		"EndLine":   c.EndLine,
	}
}
