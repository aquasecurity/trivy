package armjson

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Object(t *testing.T) {
	example := []byte(`{
	"name": "testing",
	"balance": 3.14
}`)
	target := struct {
		Name    string  `json:"name"`
		Balance float64 `json:"balance"`
	}{}
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &target, &metadata))
	assert.Equal(t, "testing", target.Name)
	assert.Equal(t, 3.14, target.Balance)
}

func Test_ObjectWithPointers(t *testing.T) {
	example := []byte(`{
	"name": "testing",
	"balance": 3.14
}`)
	target := struct {
		Name    *string  `json:"name"`
		Balance *float64 `json:"balance"`
	}{}
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &target, &metadata))
	assert.Equal(t, "testing", *target.Name)
	assert.Equal(t, 3.14, *target.Balance)
}

type nestedParent struct {
	Child *nestedChild
	Name  string
}

type nestedChild struct {
	Blah string `json:"secret"`
}

func Test_ObjectWithPointerToNestedStruct(t *testing.T) {
	example := []byte(`{
	"Child": {
		"secret": "password"
	},
	"Name": "testing"
}`)

	var parent nestedParent
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &parent, &metadata))
	assert.Equal(t, "testing", parent.Name)
	assert.Equal(t, "password", parent.Child.Blah)
}

func Test_Object_ToMapStringInterface(t *testing.T) {
	example := []byte(`{
	"Name": "testing"
}`)

	parent := make(map[string]interface{})
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &parent, &metadata))
	assert.Equal(t, "testing", parent["Name"])
}

func Test_Object_ToNestedMapStringInterfaceFromIAM(t *testing.T) {
	example := []byte(`
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
          "Bool": {
              "aws:MultiFactorAuthPresent": ["true"]
          }
      }
    }
  ]
}`)

	parent := make(map[string]interface{})
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &parent, &metadata))
}

func Test_Object_ToNestedMapStringInterface(t *testing.T) {
	example := []byte(`{
	"Child": {
		"secret": "password"
	},
	"Name": "testing"
}`)

	parent := make(map[string]interface{})
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal(example, &parent, &metadata))
	assert.Equal(t, "testing", parent["Name"])
	child := parent["Child"].(map[string]interface{})
	assert.Equal(t, "password", child["secret"])
}
