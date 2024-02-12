package parser

import (
	"context"
	"testing"

	"github.com/liamg/memoryfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Parser(t *testing.T) {
	input := `---
x:
  y: 123
  z:
  - a
  - b
  - c
`

	memfs := memoryfs.New()
	err := memfs.WriteFile("something.yaml", []byte(input), 0644)
	require.NoError(t, err)

	data, err := New().ParseFile(context.TODO(), memfs, "something.yaml")
	require.NoError(t, err)

	assert.Len(t, data, 1)

	msi, ok := data[0].(map[string]interface{})
	require.True(t, ok)

	xObj, ok := msi["x"]
	require.True(t, ok)

	xMsi, ok := xObj.(map[string]interface{})
	require.True(t, ok)

	yRaw, ok := xMsi["y"]
	require.True(t, ok)

	y, ok := yRaw.(int)
	require.True(t, ok)

	assert.Equal(t, 123, y)

	zRaw, ok := xMsi["z"]
	require.True(t, ok)

	z, ok := zRaw.([]interface{})
	require.True(t, ok)

	require.Len(t, z, 3)

	assert.Equal(t, "a", z[0])
	assert.Equal(t, "b", z[1])
	assert.Equal(t, "c", z[2])

}

func Test_Parser_WithSeparatedContent(t *testing.T) {
	input := `---
x:
  y: 123
  z:
  - a
  - b
  - c
---
x:
  y: 456
  z:
  - x
  - y
  - z
`

	memfs := memoryfs.New()
	err := memfs.WriteFile("something.yaml", []byte(input), 0644)
	require.NoError(t, err)

	data, err := New().ParseFile(context.TODO(), memfs, "something.yaml")
	require.NoError(t, err)

	assert.Len(t, data, 2)

	{
		msi, ok := data[0].(map[string]interface{})
		require.True(t, ok)

		xObj, ok := msi["x"]
		require.True(t, ok)

		xMsi, ok := xObj.(map[string]interface{})
		require.True(t, ok)

		yRaw, ok := xMsi["y"]
		require.True(t, ok)

		y, ok := yRaw.(int)
		require.True(t, ok)

		assert.Equal(t, 123, y)

		zRaw, ok := xMsi["z"]
		require.True(t, ok)

		z, ok := zRaw.([]interface{})
		require.True(t, ok)

		require.Len(t, z, 3)

		assert.Equal(t, "a", z[0])
		assert.Equal(t, "b", z[1])
		assert.Equal(t, "c", z[2])
	}

	{
		msi, ok := data[1].(map[string]interface{})
		require.True(t, ok)

		xObj, ok := msi["x"]
		require.True(t, ok)

		xMsi, ok := xObj.(map[string]interface{})
		require.True(t, ok)

		yRaw, ok := xMsi["y"]
		require.True(t, ok)

		y, ok := yRaw.(int)
		require.True(t, ok)

		assert.Equal(t, 456, y)

		zRaw, ok := xMsi["z"]
		require.True(t, ok)

		z, ok := zRaw.([]interface{})
		require.True(t, ok)

		require.Len(t, z, 3)

		assert.Equal(t, "x", z[0])
		assert.Equal(t, "y", z[1])
		assert.Equal(t, "z", z[2])
	}

}
