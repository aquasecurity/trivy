package resolvers_test

import (
	"context"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
)

type moduleResolver interface {
	Resolve(context.Context, fs.FS, resolvers.Options) (fs.FS, string, string, bool, error)
}

func TestResolveModuleFromCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tests := []struct {
		name          string
		opts          resolvers.Options
		firstResolver moduleResolver
	}{
		{
			name: "registry",
			opts: resolvers.Options{
				Name:    "bucket",
				Source:  "terraform-aws-modules/s3-bucket/aws",
				Version: "4.1.2",
			},
			firstResolver: resolvers.Registry,
		},
		{
			name: "registry with subdir",
			opts: resolvers.Options{
				Name:    "object",
				Source:  "terraform-aws-modules/s3-bucket/aws//modules/object",
				Version: "4.1.2",
			},
			firstResolver: resolvers.Registry,
		},
		{
			name: "remote",
			opts: resolvers.Options{
				Name:   "bucket",
				Source: "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v4.1.2",
			},
			firstResolver: resolvers.Remote,
		},
		{
			name: "remote with subdir",
			opts: resolvers.Options{
				Name:   "object",
				Source: "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git//modules/object?ref=v4.1.2",
			},
			firstResolver: resolvers.Remote,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tt.opts.AllowDownloads = true
			tt.opts.OriginalSource = tt.opts.Source
			tt.opts.OriginalVersion = tt.opts.Version
			tt.opts.CacheDir = t.TempDir()

			fsys, _, _, applies, err := tt.firstResolver.Resolve(context.Background(), nil, tt.opts)
			require.NoError(t, err)
			assert.True(t, applies)

			_, err = fs.Stat(fsys, "main.tf")
			require.NoError(t, err)

			_, _, _, applies, err = resolvers.Cache.Resolve(context.Background(), fsys, tt.opts)
			require.NoError(t, err)
			assert.True(t, applies)
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
	})
	require.NoError(t, err)
	assert.True(t, applies)
}
