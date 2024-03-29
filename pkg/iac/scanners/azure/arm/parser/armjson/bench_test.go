package armjson

import (
	"encoding/json"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/stretchr/testify/require"
)

func BenchmarkUnmarshal_JFather(b *testing.B) {
	target := make(map[string]interface{})
	input := []byte(`{
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
}`)

	for n := 0; n < b.N; n++ {
		metadata := types.NewTestMetadata()
		require.NoError(b, Unmarshal(input, &target, &metadata))
	}
}

func BenchmarkUnmarshal_Traditional(b *testing.B) {
	target := make(map[string]interface{})
	input := []byte(`{
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
}`)

	for n := 0; n < b.N; n++ {
		require.NoError(b, json.Unmarshal(input, &target))
	}
}
