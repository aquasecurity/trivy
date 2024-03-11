package armjson

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/require"
)

func Test_Null(t *testing.T) {
	example := []byte(`null`)
	var output string
	ref := &output
	metadata := types.NewTestMetadata()
	err := Unmarshal(example, &ref, &metadata)
	require.NoError(t, err)
}
