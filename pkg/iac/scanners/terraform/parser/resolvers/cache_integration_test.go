//go:build unix

package resolvers_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/gittest"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/log"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

func testOptions(t *testing.T, source string) resolvers.Options {
	return resolvers.Options{
		Source:          source,
		OriginalSource:  source,
		Version:         "",
		OriginalVersion: "",
		AllowDownloads:  true,
		CacheDir:        t.TempDir(),
		Logger:          log.WithPrefix("test"),
	}
}

func newRegistry(repoURL string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/modules/terraform-aws-modules/s3-bucket/aws/download", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Terraform-Get", repoURL)
		w.WriteHeader(http.StatusNoContent)
	})

	return httptest.NewTLSServer(mux)
}

func buildGitSource(repoURL string) string { return "git::" + repoURL }

func TestResolveModuleFromCache(t *testing.T) {

	repo := "terraform-aws-s3-bucket"
	gs := gittest.NewServer(t, repo, "testdata/terraform-aws-s3-bucket", gittest.Options{})
	defer gs.Close()

	repoURL := gs.URL + "/" + repo + ".git"

	registry := newRegistry(buildGitSource(repoURL))
	defer registry.Close()

	registryAddress := strings.TrimPrefix(registry.URL, "https://")

	tests := []struct {
		name           string
		opts           resolvers.Options
		firstResolver  resolvers.ModuleResolver
		expectedSubdir string
		expectedString string
	}{
		{
			name: "registry",
			opts: resolvers.Options{
				Source: registryAddress + "/terraform-aws-modules/s3-bucket/aws",
				Client: &http.Client{
					Transport: xhttp.NewTransport(xhttp.Options{Insecure: true}).Build(),
				},
			},
			firstResolver:  resolvers.Registry,
			expectedSubdir: ".",
			expectedString: "# AWS S3 bucket Terraform module",
		},
		{
			name: "registry with subdir",
			opts: resolvers.Options{
				Source: registryAddress + "/terraform-aws-modules/s3-bucket/aws//modules/object",
				Client: &http.Client{
					Transport: xhttp.NewTransport(xhttp.Options{Insecure: true}).Build(),
				},
			},
			firstResolver:  resolvers.Registry,
			expectedSubdir: "modules/object",
			expectedString: "# S3 bucket object",
		},
		{
			name: "remote",
			opts: resolvers.Options{
				Source: buildGitSource(repoURL),
			},
			firstResolver:  resolvers.Remote,
			expectedSubdir: ".",
			expectedString: "# AWS S3 bucket Terraform module",
		},
		{
			name: "remote with subdir",
			opts: resolvers.Options{
				Source: buildGitSource(repoURL) + "//modules/object",
			},
			firstResolver:  resolvers.Remote,
			expectedSubdir: "modules/object",
			expectedString: "# S3 bucket object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tt.opts.OriginalSource = tt.opts.Source
			tt.opts.AllowDownloads = true
			tt.opts.CacheDir = t.TempDir()
			tt.opts.Logger = log.WithPrefix("test")

			res, err := tt.firstResolver.Resolve(t.Context(), nil, tt.opts)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSubdir, res.Dir)

			b, err := fs.ReadFile(res.FS, path.Join(res.Dir, "README.md"))
			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, string(b))

			cached, err := resolvers.Cache.Resolve(t.Context(), res.FS, tt.opts)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSubdir, cached.Dir)

			b, err = fs.ReadFile(res.FS, path.Join(cached.Dir, "README.md"))
			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, string(b))
		})
	}
}

func TestResolveModuleFromCacheWithDifferentSubdir(t *testing.T) {
	repo := "terraform-aws-s3-bucket"
	gs := gittest.NewServer(t, repo, "testdata/terraform-aws-s3-bucket", gittest.Options{})
	defer gs.Close()

	repoURL := gs.URL + "/" + repo + ".git"

	res, err := resolvers.Remote.Resolve(
		t.Context(), nil,
		testOptions(t, "git::"+repoURL+"//modules/object"),
	)
	require.NoError(t, err)

	b, err := fs.ReadFile(res.FS, path.Join(res.Dir, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, "# S3 bucket object", string(b))

	res, err = resolvers.Remote.Resolve(
		t.Context(), nil,
		testOptions(t, "git::"+repoURL+"//modules/notification"),
	)
	require.NoError(t, err)

	b, err = fs.ReadFile(res.FS, path.Join(res.Dir, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, "# S3 bucket notification", string(b))
}
