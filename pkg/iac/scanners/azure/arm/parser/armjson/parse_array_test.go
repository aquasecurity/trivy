package armjson

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Array_Empty(t *testing.T) {
	example := []byte(`[]`)
	var target []int
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &target, &metadata))
	assert.Empty(t, target)
}

func Test_Array_ToSlice(t *testing.T) {
	example := []byte(`[1, 2, 3]`)
	var target []int
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &target, &metadata))
	assert.Len(t, target, 3)
	assert.EqualValues(t, []int{1, 2, 3}, target)
}

func Test_Array_ToArray(t *testing.T) {
	example := []byte(`[3, 2, 1]`)
	target := [3]int{6, 6, 6}
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &target, &metadata))
	assert.Len(t, target, 3)
	assert.EqualValues(t, [3]int{3, 2, 1}, target)
}

func Test_Array_ToInterface(t *testing.T) {
	example := []byte(`{ "List": [1, 2, 3] }`)
	target := struct {
		List any
	}{}
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &target, &metadata))
	assert.Len(t, target.List, 3)
}
