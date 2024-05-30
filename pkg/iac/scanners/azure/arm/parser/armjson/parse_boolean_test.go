package armjson

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Boolean_True(t *testing.T) {
	example := []byte(`true`)
	var output bool
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.True(t, output)
}

func Test_Boolean_False(t *testing.T) {
	example := []byte(`false`)
	var output bool
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.False(t, output)
}

func Test_Boolean_ToNonBoolPointer(t *testing.T) {
	example := []byte(`false`)
	var output string
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.Error(t, err)
}

func Test_Bool_ToUninitialisedPointer(t *testing.T) {
	example := []byte(`true`)
	var str *string
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, str, &metadata)
	require.Error(t, err)
	assert.Nil(t, str)
}

func Test_Bool_ToInterface(t *testing.T) {
	example := []byte(`true`)
	var output any
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &output, &metadata)
	require.NoError(t, err)
	assert.True(t, output.(bool))
}
