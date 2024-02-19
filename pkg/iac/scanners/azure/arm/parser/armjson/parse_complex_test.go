package armjson

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/require"
)

func Test_Complex(t *testing.T) {
	target := make(map[string]interface{})
	input := `{
    "glossary": {
        "title": "example glossary",
		"GlossDiv": {
            "title": "S",
			"GlossList": {
                "GlossEntry": {
                    "ID": "SGML",
					"SortAs": "SGML",
					"GlossTerm": "Standard Generalized Markup Language",
					"Acronym": "SGML",
					"Abbrev": "ISO 8879:1986",
					"GlossDef": {
                        "para": "A meta-markup language, used to create markup languages such as DocBook.",
						"GlossSeeAlso": ["GML", "XML"]
                    },
					"GlossSee": "markup"
                }
            }
        }
    }
}`
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal([]byte(input), &target, &metadata))
}

type Resource struct {
	Line  int
	inner resourceInner
}

type resourceInner struct {
	Type       string               `json:"Type" yaml:"Type"`
	Properties map[string]*Property `json:"Properties" yaml:"Properties"`
}

func (r *Resource) UnmarshalJSONWithMetadata(node Node) error {
	r.Line = node.Range().Start.Line
	return node.Decode(&r.inner)
}

type Parameter struct {
	inner parameterInner
}

type parameterInner struct {
	Type    string      `json:"Type" yaml:"Type"`
	Default interface{} `yaml:"Default"`
}

func (p *Parameter) UnmarshalJSONWithMetadata(node Node) error {
	return node.Decode(&p.inner)
}

type Property struct {
	Line  int
	inner propertyInner
}

type CFType string

type propertyInner struct {
	Type  CFType
	Value interface{} `json:"Value" yaml:"Value"`
}

func (p *Property) UnmarshalJSONWithMetadata(node Node) error {
	p.Line = node.Range().Start.Line
	return node.Decode(&p.inner)
}

type Temp struct {
	BucketName       *Parameter
	BucketKeyEnabled *Parameter
}

type FileContext struct {
	Parameters map[string]*Parameter `json:"Parameters" yaml:"Parameters"`
	Resources  map[string]*Resource  `json:"Resources" yaml:"Resources"`
}

func Test_CloudFormation(t *testing.T) {
	var target FileContext
	input := `
{
  "Parameters": {
   "BucketName":  {
      "Type": "String",
      "Default": "naughty"
    },
	"BucketKeyEnabled": {
      "Type": "Boolean",
      "Default": false
    }
  },
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": {
          "Ref": "BucketName"
        },
        "BucketEncryption": {
          "ServerSideEncryptionConfiguration": [
            {
              "BucketKeyEnabled": {
                "Ref": "BucketKeyEnabled"
              }
            }
          ]
        }
      }
    }
  }
}
`
	metadata := types.NewTestMetadata()
	require.NoError(t, Unmarshal([]byte(input), &target, &metadata))
}
