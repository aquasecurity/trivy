package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
)

type adaptFn[T any] func(fctx parser.FileContext) T

func AdaptAndCompare[T any](t *testing.T, source string, expected any, fn adaptFn[T]) {
	fsys := testutil.CreateFS(t, map[string]string{
		"main.yaml": source,
	})

	fctx, err := parser.New().ParseFile(context.TODO(), fsys, "main.yaml")
	require.NoError(t, err)

	adapted := fn(*fctx)
	testutil.AssertDefsecEqual(t, expected, adapted)
}
