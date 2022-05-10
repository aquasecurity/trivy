package dockerfile

// NOTE: we are currently preserving mixed case json here for backward compatibility

// Dockerfile represents a parsed Dockerfile
type Dockerfile struct {
	Stages map[string][]Command
}

func (d Dockerfile) ToRego() map[string]interface{} {

	stages := make(map[string]interface{})
	for from, commands := range d.Stages {
		var converted []map[string]interface{}
		for _, command := range commands {
			converted = append(converted, command.ToRego())
		}
		stages[from] = converted
	}

	return map[string]interface{}{
		"stages": stages,
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

func (c Command) ToRego() map[string]interface{} {
	return map[string]interface{}{
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
