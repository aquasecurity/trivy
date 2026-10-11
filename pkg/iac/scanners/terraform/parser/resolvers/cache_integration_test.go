//go:build unix

package resolvers_test

import (
	"context"
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

type moduleResolver interface {
	Resolve(context.Context, fs.FS, resolvers.Options) (fs.FS, string, string, bool, error)
}

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

// newDiscoveredRegistry serves the module API under a non-default path advertised through
// /.well-known/terraform.json, the way HCP Terraform and GitLab do. Nothing is served under
// /v1/modules/, so a resolver that skips discovery cannot pass.
func newDiscoveredRegistry(t *testing.T, repoURL string) (*httptest.Server, *int) {
	const modulesPath = "/api/registry/v1/modules/"
	var downloads int

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/terraform.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"modules.v1":"` + modulesPath + `"}`))
	})
	mux.HandleFunc(modulesPath+"terraform-aws-modules/s3-bucket/aws/versions", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"modules":[{"versions":[{"version":"1.0.0"},{"version":"1.2.0"},{"version":"2.0.0"}]}]}`))
	})
	mux.HandleFunc(modulesPath+"terraform-aws-modules/s3-bucket/aws/1.2.0/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		downloads++
		w.Header().Set("X-Terraform-Get", repoURL)
		w.WriteHeader(http.StatusNoContent)
	})

	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts, &downloads
}

func buildGitSource(repoURL string) string { return "git::" + repoURL }

func TestResolveModuleThroughDiscoveredEndpoint(t *testing.T) {
	repo := "terraform-aws-s3-bucket"
	gs := gittest.NewServer(t, repo, "testdata/terraform-aws-s3-bucket", gittest.Options{})
	repoURL := gs.URL + "/" + repo + ".git"

	registry, downloads := newDiscoveredRegistry(t, buildGitSource(repoURL))
	registryAddress := strings.TrimPrefix(registry.URL, "https://")
	t.Setenv("TF_TOKEN_"+strings.ReplaceAll(registryAddress, ".", "_"), "test-token")

	opts := resolvers.Options{
		Source:          registryAddress + "/terraform-aws-modules/s3-bucket/aws//modules/object",
		OriginalSource:  registryAddress + "/terraform-aws-modules/s3-bucket/aws//modules/object",
		Version:         "~> 1.0",
		OriginalVersion: "~> 1.0",
		AllowDownloads:  true,
		CacheDir:        t.TempDir(),
		Logger:          log.WithPrefix("test"),
		Client: &http.Client{
			Transport: xhttp.NewTransport(xhttp.Options{Insecure: true}).Build(),
		},
	}

	fsys, _, dir, applies, err := resolvers.Registry.Resolve(t.Context(), nil, opts)
	require.NoError(t, err)
	assert.True(t, applies)
	assert.Equal(t, "modules/object", dir)
	assert.Equal(t, 1, *downloads, "the download must go through the discovered endpoint")

	b, err := fs.ReadFile(fsys, path.Join(dir, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, "# S3 bucket object", string(b))
}

func TestResolveModuleFromCache(t *testing.T) {

	repo := "terraform-aws-s3-bucket"
	gs := gittest.NewServer(t, repo, "testdata/terraform-aws-s3-bucket", gittest.Options{})

	repoURL := gs.URL + "/" + repo + ".git"

	registry := newRegistry(buildGitSource(repoURL))
	defer registry.Close()

	registryAddress := strings.TrimPrefix(registry.URL, "https://")

	tests := []struct {
		name           string
		opts           resolvers.Options
		firstResolver  moduleResolver
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

			fsys, _, dir, _, err := tt.firstResolver.Resolve(t.Context(), nil, tt.opts)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSubdir, dir)

			b, err := fs.ReadFile(fsys, path.Join(dir, "README.md"))
			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, string(b))

			_, _, dir, _, err = resolvers.Cache.Resolve(t.Context(), fsys, tt.opts)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSubdir, dir)

			b, err = fs.ReadFile(fsys, path.Join(dir, "README.md"))
			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, string(b))
		})
	}
}

func TestResolveModuleFromCacheWithDifferentSubdir(t *testing.T) {
	repo := "terraform-aws-s3-bucket"
	gs := gittest.NewServer(t, repo, "testdata/terraform-aws-s3-bucket", gittest.Options{})

	repoURL := gs.URL + "/" + repo + ".git"

	fsys, _, dir, _, err := resolvers.Remote.Resolve(
		t.Context(), nil,
		testOptions(t, "git::"+repoURL+"//modules/object"),
	)
	require.NoError(t, err)

	b, err := fs.ReadFile(fsys, path.Join(dir, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, "# S3 bucket object", string(b))

	fsys, _, dir, _, err = resolvers.Remote.Resolve(
		t.Context(), nil,
		testOptions(t, "git::"+repoURL+"//modules/notification"),
	)
	require.NoError(t, err)

	b, err = fs.ReadFile(fsys, path.Join(dir, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, "# S3 bucket notification", string(b))
}
