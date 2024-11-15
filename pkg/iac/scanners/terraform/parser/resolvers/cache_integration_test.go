package resolvers_test

import (
	"bufio"
	"context"
	"io/fs"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/log"
)

type moduleResolver interface {
	Resolve(context.Context, fs.FS, resolvers.Options) (fs.FS, string, string, bool, error)
}

func TestResolveModuleFromCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

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
				Name:    "bucket",
				Source:  "terraform-aws-modules/s3-bucket/aws",
				Version: "4.1.2",
			},
			firstResolver:  resolvers.Registry,
			expectedSubdir: ".",
			expectedString: "# AWS S3 bucket Terraform module",
		},
		{
			name: "registry with subdir",
			opts: resolvers.Options{
				Name:    "object",
				Source:  "terraform-aws-modules/s3-bucket/aws//modules/object",
				Version: "4.1.2",
			},
			firstResolver:  resolvers.Registry,
			expectedSubdir: "modules/object",
			expectedString: "# S3 bucket object",
		},
		{
			name: "remote",
			opts: resolvers.Options{
				Name:   "bucket",
				Source: "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v4.1.2",
			},
			firstResolver:  resolvers.Remote,
			expectedSubdir: ".",
			expectedString: "# AWS S3 bucket Terraform module",
		},
		{
			name: "remote with subdir",
			opts: resolvers.Options{
				Name:   "object",
				Source: "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git//modules/object?ref=v4.1.2",
			},
			firstResolver:  resolvers.Remote,
			expectedSubdir: "modules/object",
			expectedString: "# S3 bucket object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tt.opts.AllowDownloads = true
			tt.opts.OriginalSource = tt.opts.Source
			tt.opts.OriginalVersion = tt.opts.Version
			tt.opts.CacheDir = t.TempDir()
			tt.opts.Logger = log.WithPrefix("test")

			fsys, _, subdir, applies, err := tt.firstResolver.Resolve(context.Background(), nil, tt.opts)
			require.NoError(t, err)
			assert.True(t, applies)
			assert.Equal(t, tt.expectedSubdir, subdir)

			f, err := fsys.Open(path.Join(tt.expectedSubdir, "README.md"))
			require.NoError(t, err)

			r := bufio.NewReader(f)
			line, _, err := r.ReadLine()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, string(line))

			_, _, subdir, applies, err = resolvers.Cache.Resolve(context.Background(), fsys, tt.opts)
			require.NoError(t, err)
			assert.True(t, applies)
			assert.Equal(t, tt.expectedSubdir, subdir)
		})
	}
}

func TestResolveModuleFromCacheWithDifferentSubdir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cacheDir := t.TempDir()

	fsys, _, _, applies, err := resolvers.Remote.Resolve(context.Background(), nil, resolvers.Options{
		Name:           "object",
		Source:         "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git//modules/object?ref=v4.1.2",
		OriginalSource: "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git//modules/object?ref=v4.1.2",
		AllowDownloads: true,
		CacheDir:       cacheDir,
		Logger:         log.WithPrefix("test"),
	})
	require.NoError(t, err)
	assert.True(t, applies)

	_, err = fs.Stat(fsys, "main.tf")
	require.NoError(t, err)

	_, _, _, applies, err = resolvers.Cache.Resolve(context.Background(), nil, resolvers.Options{
		Name:           "notification",
		Source:         "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git//modules/notification?ref=v4.1.2",
		OriginalSource: "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git//modules/notification?ref=v4.1.2",
		CacheDir:       cacheDir,
		Logger:         log.WithPrefix("test"),
	})
	require.NoError(t, err)
	assert.True(t, applies)
}
