package json_test

import (
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/c/conan"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

// See npm.LockFile
type nestedStruct struct {
	Dependencies map[string]Dependency `json:"dependencies"`
}

type Dependency struct {
	Version      string                `json:"version"`
	Dependencies map[string]Dependency `json:"dependencies"`
	types.Location
}

func (d *Dependency) SetLocation(location types.Location) {
	d.Location = location
}

var (
	nestedLocationObject = []byte(`
{
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
}`)

	onlyString = []byte(`
{
    "version": "0.5",
    "requires": [
        "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
        "matrix/1.3#905c3f0babc520684c84127378fefdd0%1675278900.0103245"
    ]
}`)
)

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		out  any
		want any
	}{
		{
			name: "nested LocationObjects",
			in:   nestedLocationObject,
			out:  nestedStruct{},
			want: nestedStruct{
				Dependencies: map[string]Dependency{
					"body-parser": {
						Version: "1.18.3",
						Location: types.Location{
							StartLine: 4,
							EndLine:   11,
						},
						Dependencies: map[string]Dependency{
							// UnmarshalerWithObjectLocation doesn't support Location for nested objects
							"debug": {
								Version: "2.6.9",
							},
						},
					},
				},
			},
		},
		{
			name: "Location for only string",
			in:   onlyString,
			out:  conan.LockFile{},
			want: conan.LockFile{
				Requires: []conan.Require{
					{
						Dependency: "sound32/1.0#83d4b7bf607b3b60a6546f8b58b5cdd7%1675278904.0791488",
						Location: xjson.Location{
							Location: types.Location{
								StartLine: 5,
								EndLine:   5,
							},
						},
					},
					{
						Dependency: "matrix/1.3#905c3f0babc520684c84127378fefdd0%1675278900.0103245",
						Location: xjson.Location{
							Location: types.Location{
								StartLine: 6,
								EndLine:   6,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := json.Unmarshal(tt.in, &tt.out, json.WithUnmarshalers(xjson.UnmarshalerWithObjectLocation(tt.in)))
			require.NoError(t, err)

			require.Equal(t, tt.want, tt.out)
		})
	}

}
