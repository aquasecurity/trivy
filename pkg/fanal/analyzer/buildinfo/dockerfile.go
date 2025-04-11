package buildinfo

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/samber/lo"
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
	// ported from https://github.com/moby/buildkit/blob/e83d79a51fb49aeb921d8a2348ae14a58701c98c/frontend/dockerfile/dockerfile2llb/convert.go#L88-L89
	dockerfile, err := parser.Parse(target.Content)
	if err != nil {
		return nil, xerrors.Errorf("dockerfile parse error: %w", err)
	}

	stages, metaArgs, err := instructions.Parse(dockerfile.AST, nil)
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
	envs := metaArgsToEnvGetter(args)
	var component, arch string
	for _, st := range stages {
		for _, cmd := range st.Commands {
			switch c := cmd.(type) {
			case *instructions.EnvCommand:
				envs.addKeyValuePairsToEnvGetter(c.Env)
			case *instructions.LabelCommand:
				for _, kvp := range c.Labels {
					workResult, err := shlex.ProcessWordWithMatches(kvp.Key, envs)
					if err != nil {
						return nil, xerrors.Errorf("unable to evaluate the label '%s': %w", kvp.Key, err)
					}

					key := strings.ToLower(workResult.Result)
					if key == "com.redhat.component" || key == "bzcomponent" {
						workResult, err = shlex.ProcessWordWithMatches(kvp.Value, envs)
						component = workResult.Result
					} else if key == "architecture" {
						workResult, err = shlex.ProcessWordWithMatches(kvp.Value, envs)
						arch = workResult.Result
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

type envGetter struct {
	m map[string]string
}

func (e *envGetter) addKeyValuePairsToEnvGetter(kvp instructions.KeyValuePairs) {
	if e.m == nil {
		e.m = make(map[string]string)
	}

	for _, kv := range kvp {
		e.m[kv.Key] = kv.Value
	}
}

func metaArgsToEnvGetter(metaArgs []instructions.KeyValuePairOptional) *envGetter {
	env := &envGetter{
		m: make(map[string]string),
	}

	for _, kv := range metaArgs {
		env.m[kv.Key] = kv.ValueString()
	}
	return env
}

func (e *envGetter) Get(key string) (string, bool) {
	v, ok := e.m[key]
	return v, ok
}

func (e *envGetter) Keys() []string {
	return lo.Keys(e.m)
}

func setKVValue(kvpo instructions.KeyValuePairOptional, values map[string]string) instructions.KeyValuePairOptional {
	if v, ok := values[kvpo.Key]; ok {
		kvpo.Value = &v
	}
	return kvpo
}

func (a dockerfileAnalyzer) StaticPaths() []string {
	return []string{"root/buildinfo"}
}
