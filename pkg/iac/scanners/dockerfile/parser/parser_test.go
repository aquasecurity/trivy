package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Parser(t *testing.T) {
	input := `FROM ubuntu:18.04
COPY . /app
RUN make /app
CMD python /app/app.py
`

	df, err := New().parse("Dockerfile", strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, 1, len(df.Stages))

	require.Len(t, df.Stages, 1)

	assert.Equal(t, "ubuntu:18.04", df.Stages[0].Name)
	commands := df.Stages[0].Commands
	assert.Equal(t, 4, len(commands))

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
