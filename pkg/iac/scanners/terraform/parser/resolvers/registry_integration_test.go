package resolvers_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestResolveModuleFromOpenTofuRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	fsys, _, path, _, err := resolvers.Registry.Resolve(context.Background(), nil, resolvers.Options{
		Source:          "registry.opentofu.org/terraform-aws-modules/s3-bucket/aws",
		OriginalSource:  "registry.opentofu.org/terraform-aws-modules/s3-bucket/aws",
		RelativePath:    "test",
		Name:            "bucket",
		Version:         "4.1.2",
		OriginalVersion: "4.1.2",
		AllowDownloads:  true,
		SkipCache:       true,
		Logger:          log.WithPrefix("test"),
	})
	require.NoError(t, err)

	_, err = fs.Stat(fsys, filepath.Join(path, "main.tf"))
	require.NoError(t, err)
}
