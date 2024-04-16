package armjson

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var input = `abcdefghijklmnopqrstuvwxyz`

func Test_Peeker(t *testing.T) {
	peeker := NewPeekReader(strings.NewReader(input))

	var b rune
	var err error

	for i := 0; i < 30; i++ {
		b, err = peeker.Peek()
		require.NoError(t, err)
		assert.Equal(t, ('a'), b)
	}

	b, err = peeker.Next()
	require.NoError(t, err)
	assert.Equal(t, ('a'), b)

	b, err = peeker.Next()
	require.NoError(t, err)
	assert.Equal(t, ('b'), b)

	b, err = peeker.Peek()
	require.NoError(t, err)
	assert.Equal(t, ('c'), b)

	for i := 0; i < 5; i++ {
		b, err = peeker.Next()
		require.NoError(t, err)
		assert.Equal(t, []rune(input)[2+i], b)
	}

	b, err = peeker.Peek()
	require.NoError(t, err)
	assert.Equal(t, ('h'), b)

	b, err = peeker.Next()
	require.NoError(t, err)
	assert.Equal(t, ('h'), b)
	for i := 0; i < 18; i++ {
		b, err = peeker.Next()
		require.NoError(t, err)
		assert.Equal(t, []rune(input)[8+i], b)
	}

	_, err = peeker.Peek()
	require.Error(t, err)

	_, err = peeker.Next()
	require.Error(t, err)

}
