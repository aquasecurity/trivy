package result

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIgnoreFile(t *testing.T) {
	t.Run("happy path valid config file", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "testdata/.trivyignore")
		require.NoError(t, err)
		assert.Equal(t, "testdata/.trivyignore", got.FilePath)

		// IDs in .trivyignore are treated as IDs for all scanners
		// as it is unclear which type of security issue they are
		assert.Len(t, got.Vulnerabilities, 8)
		assert.Len(t, got.Misconfigurations, 8)
		assert.Len(t, got.Secrets, 8)
		assert.Len(t, got.Licenses, 8)
	})

	t.Run("happy path valid YAML config file", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "testdata/.trivyignore.yaml")
		require.NoError(t, err)
		assert.Equal(t, "testdata/.trivyignore.yaml", got.FilePath)
		assert.Len(t, got.Vulnerabilities, 5)
		assert.Len(t, got.Misconfigurations, 4)
		assert.Len(t, got.Secrets, 3)
		assert.Len(t, got.Licenses, 5)
	})

	t.Run("empty YAML file passed", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "TestParseIgnoreFile-*.yaml")
		require.NoError(t, err)
		defer f.Close()

		_, err = ParseIgnoreFile(t.Context(), f.Name())
		require.NoError(t, err)
	})

	t.Run("invalid YAML file passed", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "TestParseIgnoreFile-*.yaml")
		require.NoError(t, err)
		defer f.Close()

		_, err = f.WriteString("this file is not a yaml file")
		require.NoError(t, err)

		got, err := ParseIgnoreFile(t.Context(), f.Name())
		require.ErrorContains(t, err, "yaml decode error")
		assert.Empty(t, got)
	})

	t.Run("invalid file passed", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "TestParseIgnoreFile-*")
		require.NoError(t, err)
		defer f.Close()

		_, err = f.WriteString("this file is not a valid trivyignore file")
		require.NoError(t, err)

		_, err = ParseIgnoreFile(t.Context(), f.Name())
		require.NoError(t, err) // TODO(simar7): We don't verify correctness, should we?
	})

	t.Run("non existing file passed", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "does-not-exist.yaml")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

}
