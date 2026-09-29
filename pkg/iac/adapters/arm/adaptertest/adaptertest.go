package adaptertest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser"
)

type adaptFn[T any] func(deployment azure.Deployment) T

func AdaptAndCompare[T any](t *testing.T, source string, expected any, fn adaptFn[T]) {
	fsys := testutil.CreateFS(map[string]string{
		"test.json": source,
	})

	deployments, err := parser.New(fsys).ParseFS(t.Context(), ".")
	require.NoError(t, err)
	require.Len(t, deployments, 1)

	adapted := fn(deployments[0])
	testutil.AssertDefsecEqual(t, expected, adapted)
}
