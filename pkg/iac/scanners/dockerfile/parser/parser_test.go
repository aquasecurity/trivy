package parser_test

import (
	"context"
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

	res, err := parser.Parse(context.TODO(), strings.NewReader(input), "Dockerfile")
	require.NoError(t, err)

	df, ok := res.(*dockerfile.Dockerfile)
	require.True(t, ok)

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
			res, err := parser.Parse(context.TODO(), strings.NewReader(tt.src), "Dockerfile")
			require.NoError(t, err)

			df, ok := res.(*dockerfile.Dockerfile)
			require.True(t, ok)

			cmd := df.Stages[0].Commands[0]

			assert.Equal(t, tt.src, cmd.Original)
			assert.Equal(t, []string{tt.expected}, cmd.Value)
		})
	}
}
