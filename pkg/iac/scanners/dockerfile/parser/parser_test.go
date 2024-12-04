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
