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

	t.Run("valid YAML config file without ids", func(t *testing.T) {
		got, err := ParseIgnoreFile(t.Context(), "testdata/.trivyignore-no-id.yaml")
		require.NoError(t, err)
		assert.Len(t, got.Vulnerabilities, 2)
		assert.Len(t, got.Misconfigurations, 1)
		assert.Len(t, got.Secrets, 1)
		assert.Len(t, got.Licenses, 1)
	})

	t.Run("entry without id, purls, and paths", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "TestParseIgnoreFile-*.yaml")
		require.NoError(t, err)
		defer f.Close()

		_, err = f.WriteString(`vulnerabilities:
  - statement: matches nothing
`)
		require.NoError(t, err)

		_, err = ParseIgnoreFile(t.Context(), f.Name())
		require.ErrorContains(t, err, "at least one of id, purls, or paths must be specified")
	})

}

func TestIgnoreFindingsMatch(t *testing.T) {
	linuxLibcDev, err := purl.FromString("pkg:deb/ubuntu/linux-libc-dev@5.15.0")
	require.NoError(t, err)
	otherPkg, err := purl.FromString("pkg:deb/ubuntu/other-pkg@1.0.0")
	require.NoError(t, err)

	tests := []struct {
		name     string
		findings IgnoreFindings
		id       string
		path     string
		pkg      *packageurl.PackageURL
		want     bool
	}{
		{
			name: "entry without id matches a vulnerability by purl",
			findings: IgnoreFindings{
				{PURLs: []*purl.PackageURL{linuxLibcDev}},
			},
			id:   "CVE-2024-0001",
			pkg:  linuxLibcDev.Unwrap(),
			want: true,
		},
		{
			name: "entry without id does not match other packages",
			findings: IgnoreFindings{
				{PURLs: []*purl.PackageURL{linuxLibcDev}},
			},
			id:   "CVE-2024-0001",
			pkg:  otherPkg.Unwrap(),
			want: false,
		},
		{
			name: "entry without id matches a finding by path pattern",
			findings: IgnoreFindings{
				{Paths: []string{"test/fixtures/**"}},
			},
			id:   "AVD-AWS-0001",
			path: "test/fixtures/main.tf",
			want: true,
		},
		{
			name: "entry without id does not match other paths",
			findings: IgnoreFindings{
				{Paths: []string{"test/fixtures/**"}},
			},
			id:   "AVD-AWS-0001",
			path: "main.tf",
			want: false,
		},
		{
			name: "entry without id matches any finding id",
			findings: IgnoreFindings{
				{Paths: []string{"test/fixtures/**"}},
			},
			id:   "CVE-2024-0002",
			path: "test/fixtures/Dockerfile",
			want: true,
		},
		{
			name: "entry with id still requires id equality",
			findings: IgnoreFindings{
				{ID: "CVE-2024-0002", PURLs: []*purl.PackageURL{linuxLibcDev}},
			},
			id:   "CVE-2024-0001",
			pkg:  linuxLibcDev.Unwrap(),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.findings.Match(tt.id, tt.path, tt.pkg)
			if tt.want {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}
