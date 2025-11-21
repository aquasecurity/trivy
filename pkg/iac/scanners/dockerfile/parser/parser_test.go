package parser_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/providers/dockerfile"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile/parser"
)

func Test_Parser(t *testing.T) {
	input := `FROM ubuntu:18.04
COPY . /app
RUN make /app
CMD python /app/app.py
`

	dfs, err := parser.Parse(t.Context(), strings.NewReader(input), "Dockerfile")
	require.NoError(t, err)
	require.Len(t, dfs, 1)

	df := dfs[0]
	assert.Len(t, df.Stages, 1)

	assert.Equal(t, "ubuntu:18.04", df.Stages[0].Name)
	commands := df.Stages[0].Commands
	assert.Len(t, commands, 4)

	// FROM ubuntu:18.04
	assert.Equal(t, "from", commands[0].Cmd)
	assert.Equal(t, "ubuntu:18.04", commands[0].Value[0])
	assert.Equal(t, "Dockerfile", commands[0].Path)
	assert.Equal(t, 1, commands[0].StartLine)
	assert.Equal(t, 1, commands[0].EndLine)

	// COPY . /app
	assert.Equal(t, "copy", commands[1].Cmd)
	assert.Equal(t, ". /app", strings.Join(commands[1].Value, " "))
	assert.Equal(t, "Dockerfile", commands[1].Path)
	assert.Equal(t, 2, commands[1].StartLine)
	assert.Equal(t, 2, commands[1].EndLine)

	// RUN make /app
	assert.Equal(t, "run", commands[2].Cmd)
	assert.Equal(t, "make /app", commands[2].Value[0])
	assert.Equal(t, "Dockerfile", commands[2].Path)
	assert.Equal(t, 3, commands[2].StartLine)
	assert.Equal(t, 3, commands[2].EndLine)

	// CMD python /app/app.py
	assert.Equal(t, "cmd", commands[3].Cmd)
	assert.Equal(t, "python /app/app.py", commands[3].Value[0])
	assert.Equal(t, "Dockerfile", commands[3].Path)
	assert.Equal(t, 4, commands[3].StartLine)
	assert.Equal(t, 4, commands[3].EndLine)
}

func TestParserUnknownFlags(t *testing.T) {
	input := `FROM ubuntu:18.04
COPY --foo --chown=1 --bar=./test . /app
RUN --baz --baz --network=host make /app
ONBUILD RUN --foo make /app
CMD python /app/app.py
`
	dfs, err := parser.Parse(t.Context(), strings.NewReader(input), "Dockerfile")
	require.NoError(t, err)
	require.Len(t, dfs, 1)

	expected := &dockerfile.Dockerfile{
		Stages: []dockerfile.Stage{
			{
				Name: "ubuntu:18.04",
				Commands: []dockerfile.Command{
					{
						Cmd:       "from",
						Value:     []string{"ubuntu:18.04"},
						Flags:     []string{},
						Original:  "FROM ubuntu:18.04",
						Path:      "Dockerfile",
						StartLine: 1,
						EndLine:   1,
					},
					{
						Cmd:       "copy",
						Value:     []string{".", "/app"},
						Flags:     []string{"--chown=1"},
						Original:  "COPY --foo --chown=1 --bar=./test . /app",
						Path:      "Dockerfile",
						StartLine: 2,
						EndLine:   2,
					},
					{
						Cmd:       "run",
						Value:     []string{"make /app"},
						Flags:     []string{"--network=host"},
						Original:  "RUN --baz --baz --network=host make /app",
						Path:      "Dockerfile",
						StartLine: 3,
						EndLine:   3,
					},
					{
						Cmd:       "onbuild",
						SubCmd:    "RUN",
						Value:     []string{"make /app"},
						Flags:     []string{},
						Original:  "ONBUILD RUN --foo make /app",
						Path:      "Dockerfile",
						StartLine: 4,
						EndLine:   4,
					},
					{
						Cmd:       "cmd",
						Value:     []string{"python /app/app.py"},
						Flags:     []string{},
						Original:  "CMD python /app/app.py",
						Path:      "Dockerfile",
						StartLine: 5,
						EndLine:   5,
					},
				},
			},
		},
	}
	assert.Equal(t, expected, dfs[0])
}

func Test_ParseHeredocs(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected string
	}{
		{
			name: "multi-line script",
			src: `RUN <<EOF
apk add curl
apk add git
EOF`,
			expected: "apk add curl ; apk add git",
		},
		{
			name: "file redirection and chained command",
			src: `RUN cat <<EOF > /tmp/output && echo 'done'
hello
mr
potato
EOF`,
			expected: "cat <<EOF > /tmp/output && echo 'done'\nhello\nmr\npotato\nEOF",
		},
		{
			name: "redirect to file",
			src: `RUN <<EOF > /etc/config.yaml
key1: value1
key2: value2
EOF`,
			expected: "<<EOF > /etc/config.yaml\nkey1: value1\nkey2: value2\nEOF",
		},
		{
			name: "with a shebang",
			src: `RUN <<EOF
#!/usr/bin/env python
print("hello world")
EOF`,
			expected: "<<EOF\n#!/usr/bin/env python\nprint(\"hello world\")\nEOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dfs, err := parser.Parse(t.Context(), strings.NewReader(tt.src), "Dockerfile")
			require.NoError(t, err)
			require.Len(t, dfs, 1)

			df := dfs[0]
			require.Len(t, df.Stages, 1)

			cmd := df.Stages[0].Commands[0]

			assert.Equal(t, tt.src, cmd.Original)
			assert.Equal(t, []string{tt.expected}, cmd.Value)
		})
	}
}
