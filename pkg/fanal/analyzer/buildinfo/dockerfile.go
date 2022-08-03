package buildinfo

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&dockerfileAnalyzer{})
}

const dockerfileAnalyzerVersion = 1

// For Red Hat products
type dockerfileAnalyzer struct{}

func (a dockerfileAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// ported from https://github.com/moby/buildkit/blob/b33357bcd2e3319b0323037c900c13b45a228df1/frontend/dockerfile/dockerfile2llb/convert.go#L73
	dockerfile, err := parser.Parse(target.Content)
	if err != nil {
		return nil, xerrors.Errorf("dockerfile parse error: %w", err)
	}

	stages, metaArgs, err := instructions.Parse(dockerfile.AST)
	if err != nil {
		return nil, xerrors.Errorf("instruction parse error: %w", err)
	}

	var args []instructions.KeyValuePairOptional
	for _, cmd := range metaArgs {
		for _, metaArg := range cmd.Args {
			args = append(args, setKVValue(metaArg, nil))
		}
	}

	shlex := shell.NewLex(dockerfile.EscapeToken)
	env := metaArgsToMap(args)

	var component, arch string
	for _, st := range stages {
		for _, cmd := range st.Commands {
			switch c := cmd.(type) {
			case *instructions.EnvCommand:
				for _, kvp := range c.Env {
					env[kvp.Key] = kvp.Value
				}
			case *instructions.LabelCommand:
				for _, kvp := range c.Labels {
					key, err := shlex.ProcessWordWithMap(kvp.Key, env)
					if err != nil {
						return nil, xerrors.Errorf("unable to evaluate the label '%s': %w", kvp.Key, err)
					}

					key = strings.ToLower(key)
					if key == "com.redhat.component" || key == "bzcomponent" {
						component, err = shlex.ProcessWordWithMap(kvp.Value, env)
					} else if key == "architecture" {
						arch, err = shlex.ProcessWordWithMap(kvp.Value, env)
					}

					if err != nil {
						return nil, xerrors.Errorf("failed to process the label '%s': %w", key, err)
					}
				}
			}
		}
	}

	if component == "" {
		return nil, xerrors.New("no component found")
	} else if arch == "" {
		return nil, xerrors.New("no arch found")
	}

	return &analyzer.AnalysisResult{
		BuildInfo: &types.BuildInfo{
			Nvr:  component + "-" + parseVersion(target.FilePath),
			Arch: arch,
		},
	}, nil
}

func (a dockerfileAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, file := filepath.Split(filepath.ToSlash(filePath))
	if dir != "root/buildinfo/" {
		return false
	}
	return strings.HasPrefix(file, "Dockerfile")
}

func (a dockerfileAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRedHatDockerfileType
}

func (a dockerfileAnalyzer) Version() int {
	return dockerfileAnalyzerVersion
}

// parseVersion parses version from a file name
func parseVersion(nvr string) string {
	releaseIndex := strings.LastIndex(nvr, "-")
	if releaseIndex < 0 {
		return ""
	}
	versionIndex := strings.LastIndex(nvr[:releaseIndex], "-")
	version := nvr[versionIndex+1:]
	return version
}

// https://github.com/moby/buildkit/blob/b33357bcd2e3319b0323037c900c13b45a228df1/frontend/dockerfile/dockerfile2llb/convert.go#L474-L482
func metaArgsToMap(metaArgs []instructions.KeyValuePairOptional) map[string]string {
	m := map[string]string{}

	for _, arg := range metaArgs {
		m[arg.Key] = arg.ValueString()
	}

	return m
}

func setKVValue(kvpo instructions.KeyValuePairOptional, values map[string]string) instructions.KeyValuePairOptional {
	if v, ok := values[kvpo.Key]; ok {
		kvpo.Value = &v
	}
	return kvpo
}
