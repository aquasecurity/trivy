package result

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/purl"
)

func TestParseIgnoreFile(t *testing.T) {
	t.Run("empty path disables the default ignore file", func(t *testing.T) {
		t.Chdir(t.TempDir())
		require.NoError(t, os.WriteFile(".trivyignore", []byte("CVE-2024-1234\n"), 0o600))

		got, err := ParseIgnoreFile(t.Context(), ".trivyignore")
		require.NoError(t, err)
		assert.Len(t, got.Vulnerabilities, 1)

		got, err = ParseIgnoreFile(t.Context(), "")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("happy path valid config file", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "testdata/.trivyignore")
		require.NoError(t, err)
		assert.Equal(t, "testdata/.trivyignore", got.FilePath)

		// IDs in .trivyignore are treated as IDs for all scanners
		// as it is unclear which type of security issue they are
		assert.Len(t, got.Vulnerabilities, 9)
		assert.Len(t, got.Misconfigurations, 9)
		assert.Len(t, got.Secrets, 9)
		assert.Len(t, got.Licenses, 9)
		assert.Len(t, got.Crypto, 9)
	})

	t.Run("happy path valid YAML config file", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "testdata/.trivyignore.yaml")
		require.NoError(t, err)
		assert.Equal(t, "testdata/.trivyignore.yaml", got.FilePath)
		assert.Len(t, got.Vulnerabilities, 5)
		assert.Len(t, got.Misconfigurations, 4)
		assert.Len(t, got.Secrets, 3)
		assert.Len(t, got.Licenses, 5)
		assert.Len(t, got.Crypto, 2)
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

	t.Run("line too long", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "TestParseIgnoreFile-*")
		require.NoError(t, err)
		defer f.Close()

		_, err = f.WriteString("CVE-2024-0001\n" + strings.Repeat("A", bufio.MaxScanTokenSize) + "\nCVE-2024-0002\n")
		require.NoError(t, err)

		got, err := ParseIgnoreFile(t.Context(), f.Name())
		require.ErrorIs(t, err, bufio.ErrTooLong)
		assert.Empty(t, got)
	})

	t.Run("non existing file passed", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "does-not-exist.yaml")
		require.NoError(t, err)
		assert.Empty(t, got)
	})

}

// A `purls` entry narrows an ignore finding to specific packages. A package that
// carries no PURL cannot be one of them, so the entry must not suppress the same
// ID for it. Packages without a PURL reach this matcher, e.g. local Go modules,
// whose PURL is intentionally skipped.
func TestIgnoreFindings_Match_PURLScope(t *testing.T) {
	scoped, err := purl.FromString("pkg:deb/debian/libssl1.1")
	require.NoError(t, err)

	findings := IgnoreFindings{
		{ID: "CVE-2023-3446", PURLs: []*purl.PackageURL{scoped}},
	}

	t.Run("scoped package is ignored", func(t *testing.T) {
		got := findings.Match("CVE-2023-3446", "usr/lib/ssl", &packageurl.PackageURL{
			Type:      packageurl.TypeDebian,
			Namespace: "debian",
			Name:      "libssl1.1",
			Version:   "1.1.1n-0+deb11u5",
		})
		assert.NotNil(t, got)
	})

	t.Run("package without a purl is kept", func(t *testing.T) {
		got := findings.Match("CVE-2023-3446", "app/package.json", nil)
		assert.Nil(t, got)
	})

	t.Run("unscoped entry still matches a package without a purl", func(t *testing.T) {
		unscoped := IgnoreFindings{{ID: "CVE-2023-3446"}}
		got := unscoped.Match("CVE-2023-3446", "app/package.json", nil)
		assert.NotNil(t, got)
	})
}
