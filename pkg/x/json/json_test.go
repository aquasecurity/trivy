package json_test

import (
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/stretchr/testify/require"

	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

// See npm.LockFile
type nestedStruct struct {
	Dependencies map[string]Dependency `json:"dependencies"`
}

type Dependency struct {
	Version      string                `json:"version"`
	Dependencies map[string]Dependency `json:"dependencies"`
	xjson.Location
}

type stringWithLocation struct {
	Requires Requires `json:"requires"`
}

type Requires []Require

type Require struct {
	Dependency string
	xjson.Location
}

func (r *Require) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return json.UnmarshalDecode(dec, &r.Dependency)
}

type stringsWithoutUnmarshalerFrom struct {
	Strings []StringWithoutUnmarshalerFrom `json:"strings"`
}

type StringWithoutUnmarshalerFrom struct {
	String string
	xjson.Location
}

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		out     any
		want    any
		wantErr string
	}{
		{
			name: "nested LocationObjects",
			in: []byte(`{
    "dependencies": {
        "body-parser": {
            "version": "1.18.3",
            "dependencies": {
                "debug": {
                    "version": "2.6.9"
                }
            }
        }
    }
}`),
			out: nestedStruct{},
			want: nestedStruct{
				Dependencies: map[string]Dependency{
					"body-parser": {
						Version: "1.18.3",
						Location: xjson.Location{
							StartLine: 3,
							EndLine:   10,
						},
						Dependencies: map[string]Dependency{
							// UnmarshalerWithObjectLocation doesn't support Location for nested objects
							"debug": {
								Version: "2.6.9",
								Location: xjson.Location{
									StartLine: 6,
									EndLine:   8,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Location for only string",
			in: []byte(`{
    "version": "0.5",
    "requires": [
        "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
        "matrix/1.3#905c3f0babc520684c84127378fefdd0%1675278900.0103245"
    ]
}`),
			out: stringWithLocation{},
			want: stringWithLocation{
				Requires: []Require{
					{
						Dependency: "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
						Location: xjson.Location{
							StartLine: 4,
							EndLine:   4,
						},
					},
					{
						Dependency: "matrix/1.3#905c3f0babc520684c84127378fefdd0%1675278900.0103245",
						Location: xjson.Location{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
			},
		},
		{
			name: "String object without UnmarshalerFrom implementation",
			in: []byte(`{
    "strings": [
        "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
        "matrix/1.3#905c3f0babc520684c84127378fefdd0%1675278900.0103245"
    ]
}`),
			out:     stringsWithoutUnmarshalerFrom{},
			wantErr: "structures with single primitive type should implement UnmarshalJSONFrom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := xjson.Unmarshal(tt.in, &tt.out)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, tt.out)
		})
	}
}
