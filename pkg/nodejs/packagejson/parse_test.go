package packagejson_test

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "happypath",
			inputFile: "testdata/package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want: []types.Library{{
				ID:      "bootstrap@5.0.2",
				Name:    "bootstrap",
				Version: "5.0.2",
				License: "MIT",
			}},
			wantErr: "",
		},
		{
			name:      "happy path - legacy license",
			inputFile: "testdata/legacy_package.json",
			want: []types.Library{{
				ID:      "angular@4.1.2",
				Name:    "angular",
				Version: "4.1.2",
				License: "ISC",
			}},
			wantErr: "",
		},
		{
			name:      "sad path",
			inputFile: "testdata/invalid_package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want:    []types.Library{},
			wantErr: "JSON decode error",
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.name), func(t *testing.T) {
			f, err := os.Open(v.inputFile)
			require.NoError(t, err)

			got, _, err := packagejson.NewParser().Parse(f)
			if v.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), v.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, v.want, got)
		})
	}
}
