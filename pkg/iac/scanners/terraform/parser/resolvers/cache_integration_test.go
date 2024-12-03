//go:build unix

package resolvers_test

import (
	"context"
	"crypto/tls"
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
	mux.HandleFunc("/v1/modules/terraform-aws-modules/s3-bucket/aws/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Terraform-Get", repoURL)
		w.WriteHeader(http.StatusNoContent)
	})

	return httptest.NewTLSServer(mux)
}

func buildGitSource(repoURL string) string { return "git::" + repoURL }

func TestResolveModuleFromCache(t *testing.T) {

	repo := "terraform-aws-s3-bucket"
	gs := gittest.NewServer(t, repo, "testdata/terraform-aws-s3-bucket")
	defer gs.Close()

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
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
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
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
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

			fsys, _, dir, _, err := tt.firstResolver.Resolve(context.Background(), nil, tt.opts)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSubdir, dir)

			b, err := fs.ReadFile(fsys, path.Join(dir, "README.md"))
			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, string(b))

			_, _, dir, _, err = resolvers.Cache.Resolve(context.Background(), fsys, tt.opts)
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
	gs := gittest.NewServer(t, repo, "testdata/terraform-aws-s3-bucket")
	defer gs.Close()

	repoURL := gs.URL + "/" + repo + ".git"

	fsys, _, dir, _, err := resolvers.Remote.Resolve(
		context.Background(), nil,
		testOptions(t, "git::"+repoURL+"//modules/object"),
	)
	require.NoError(t, err)

	b, err := fs.ReadFile(fsys, path.Join(dir, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, "# S3 bucket object", string(b))

	fsys, _, dir, _, err = resolvers.Remote.Resolve(
		context.Background(), nil,
		testOptions(t, "git::"+repoURL+"//modules/notification"),
	)
	require.NoError(t, err)

	b, err = fs.ReadFile(fsys, path.Join(dir, "README.md"))
	require.NoError(t, err)
	assert.Equal(t, "# S3 bucket notification", string(b))
}
