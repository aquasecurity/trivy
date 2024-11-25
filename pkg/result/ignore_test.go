package result

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIgnoreFile(t *testing.T) {
	t.Run("happy path valid config file", func(t *testing.T) {
		got, err := ParseIgnoreFile(context.TODO(), "testdata/.trivyignore")
		require.NoError(t, err)
		assert.Equal(t, "testdata/.trivyignore", got.FilePath)

		// IDs in .trivyignore are treated as IDs for all scanners
		// as it is unclear which type of security issue they are
		assert.Len(t, got.Vulnerabilities, 6)
		assert.Len(t, got.Misconfigurations, 6)
		assert.Len(t, got.Secrets, 6)
		assert.Len(t, got.Licenses, 6)
	})

	t.Run("happy path valid YAML config file", func(t *testing.T) {
		got, err := ParseIgnoreFile(context.TODO(), "testdata/.trivyignore.yaml")
		require.NoError(t, err)
		assert.Equal(t, "testdata/.trivyignore.yaml", got.FilePath)
		assert.Len(t, got.Vulnerabilities, 5)
		assert.Len(t, got.Misconfigurations, 3)
		assert.Len(t, got.Secrets, 3)
		assert.Len(t, got.Licenses, 1)
	})

	t.Run("empty YAML file passed", func(t *testing.T) {
		f, err := os.CreateTemp("", "TestParseIgnoreFile-*.yaml")
		require.NoError(t, err)
		defer os.Remove(f.Name())

		_, err = ParseIgnoreFile(context.TODO(), f.Name())
		require.NoError(t, err)
	})

	t.Run("invalid YAML file passed", func(t *testing.T) {
		f, err := os.CreateTemp("", "TestParseIgnoreFile-*.yaml")
		require.NoError(t, err)
		defer os.Remove(f.Name())
		_, _ = f.WriteString("this file is not a yaml file")

		got, err := ParseIgnoreFile(context.TODO(), f.Name())
		assert.Contains(t, err.Error(), "yaml decode error")
		assert.Empty(t, got)
	})

	t.Run("invalid file passed", func(t *testing.T) {
		f, err := os.CreateTemp("", "TestParseIgnoreFile-*")
		require.NoError(t, err)
		defer os.Remove(f.Name())
		_, _ = f.WriteString("this file is not a valid trivyignore file")

		_, err = ParseIgnoreFile(context.TODO(), f.Name())
		require.NoError(t, err) // TODO(simar7): We don't verify correctness, should we?
	})

	t.Run("non existing file passed", func(t *testing.T) {
		got, err := ParseIgnoreFile(context.TODO(), "does-not-exist.yaml")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

}
