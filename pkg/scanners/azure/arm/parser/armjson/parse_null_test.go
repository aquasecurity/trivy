package armjson

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/stretchr/testify/require"
)

func Test_Null(t *testing.T) {
	example := []byte(`null`)
	var output string
	ref := &output
	metadata := types.NewTestMisconfigMetadata()
	err := Unmarshal(example, &ref, &metadata)
	require.NoError(t, err)
}
