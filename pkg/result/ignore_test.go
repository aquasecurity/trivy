package result

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/purl"
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

func TestIgnoreFindings_Match_withoutID(t *testing.T) {
	trivyPURL, err := purl.FromString("pkg:golang/github.com/aquasecurity/trivy@0.50.0")
	require.NoError(t, err)
	otherPURL, err := purl.FromString("pkg:golang/github.com/other/pkg@1.0.0")
	require.NoError(t, err)

	findings := IgnoreFindings{
		{
			PURLs: []*purl.PackageURL{trivyPURL},
		},
		{
			Paths: []string{"app/vendor/**"},
		},
	}

	tests := []struct {
		name  string
		id    string
		path  string
		pkg   *packageurl.PackageURL
		match bool
	}{
		{
			name:  "any ID is ignored for the selected package",
			id:    "CVE-2019-0001",
			pkg:   (*packageurl.PackageURL)(trivyPURL),
			match: true,
		},
		{
			name:  "another ID is ignored for the same package",
			id:    "CVE-2021-1234",
			pkg:   (*packageurl.PackageURL)(trivyPURL),
			match: true,
		},
		{
			name:  "another package is not ignored",
			id:    "CVE-2019-0001",
			pkg:   (*packageurl.PackageURL)(otherPURL),
			match: false,
		},
		{
			name:  "any ID is ignored under the selected path",
			id:    "CVE-2022-2222",
			path:  "app/vendor/foo/bar.go",
			match: true,
		},
		{
			name:  "another path is not ignored",
			id:    "CVE-2022-2222",
			path:  "app/main.go",
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findings.Match(tt.id, tt.path, tt.pkg)
			assert.Equal(t, tt.match, got != nil)
		})
	}
}

func TestParseIgnoreFile_withoutSelector(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".trivyignore.yaml")
	require.NoError(t, os.WriteFile(path, []byte("vulnerabilities:\n  - statement: no selector at all\n"), 0o600))

	_, err := ParseIgnoreFile(t.Context(), path)
	require.ErrorContains(t, err, "at least one of 'id', 'paths' or 'purls' must be set")
}
