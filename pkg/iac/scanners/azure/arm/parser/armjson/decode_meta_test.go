package armjson

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

type TestParent struct {
	Child *TestChild `json:"child"`
}

type TestChild struct {
	Name   string
	Line   int
	Column int
}

func (t *TestChild) UnmarshalJSONWithMetadata(node Node) error {
	t.Line = node.Range().Start.Line
	t.Column = node.Range().Start.Column
	return node.Decode(&t.Name)
}

func Test_DecodeWithMetadata(t *testing.T) {
	example := []byte(`
{
	"child": "secret"
}
`)
	var parent TestParent
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &parent, &metadata))
	assert.Equal(t, 3, parent.Child.Line)
	assert.Equal(t, 12, parent.Child.Column)
	assert.Equal(t, "secret", parent.Child.Name)
}
