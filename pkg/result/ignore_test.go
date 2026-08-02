package result

import (
	"os"
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

	t.Run("happy path id-optional yaml", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "testdata/.trivyignore-id-optional.yaml")
		require.NoError(t, err)
		assert.Len(t, got.Vulnerabilities, 3)
		assert.Len(t, got.Misconfigurations, 1)
		assert.Len(t, got.Secrets, 1)

		// First vuln entry: id empty, purls only — matches every finding for the purl.
		entry := got.Vulnerabilities[0]
		assert.Empty(t, entry.ID)
		require.Len(t, entry.PURLs, 1)
	})

	t.Run("entry with no id paths or purls is rejected", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "TestParseIgnoreFile-empty-entry-*.yaml")
		require.NoError(t, err)
		defer f.Close()

		_, err = f.WriteString("vulnerabilities:\n  - statement: matches everything\n")
		require.NoError(t, err)

		_, err = ParseIgnoreFile(t.Context(), f.Name())
		require.ErrorContains(t, err, "must specify at least one of id, paths or purls")
	})
}

func TestIgnoreFindings_Match_IDOptional(t *testing.T) {
	tests := []struct {
		name     string
		findings IgnoreFindings
		id       string
		path     string
		pkg      *packageurl.PackageURL
		matched  bool
	}{
		{
			name: "empty id with matching purl ignores any finding for the package",
			findings: IgnoreFindings{
				{
					PURLs: mustPackageURLs(t, "pkg:deb/ubuntu/linux-libc-dev"),
				},
			},
			id:      "CVE-2024-1111",
			pkg:     &packageurl.PackageURL{Type: "deb", Namespace: "ubuntu", Name: "linux-libc-dev"},
			matched: true,
		},
		{
			name: "empty id with matching purl skips findings on other packages",
			findings: IgnoreFindings{
				{
					PURLs: mustPackageURLs(t, "pkg:deb/ubuntu/linux-libc-dev"),
				},
			},
			id:      "CVE-2024-1111",
			pkg:     &packageurl.PackageURL{Type: "deb", Namespace: "ubuntu", Name: "openssl"},
			matched: false,
		},
		{
			name: "empty id with matching path ignores any finding under that path",
			findings: IgnoreFindings{
				{
					Paths: []string{"vendor/**"},
				},
			},
			id:      "AVD-AWS-0175",
			path:    "vendor/foo/bar.tf",
			matched: true,
		},
		{
			name: "non-empty id still requires id equality",
			findings: IgnoreFindings{
				{
					ID:    "CVE-2024-1111",
					Paths: []string{"vendor/**"},
				},
			},
			id:      "CVE-2024-9999",
			path:    "vendor/foo/bar.tf",
			matched: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.findings.Match(tc.id, tc.path, tc.pkg)
			if tc.matched {
				require.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func mustPackageURLs(t *testing.T, raws ...string) []*purl.PackageURL {
	t.Helper()
	out := make([]*purl.PackageURL, 0, len(raws))
	for _, raw := range raws {
		p, err := purl.FromString(raw)
		require.NoError(t, err)
		out = append(out, p)
	}
	return out
}
