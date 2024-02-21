package packagejson_test

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		name      string
		inputFile string
		want      packagejson.Package
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want: packagejson.Package{
				Library: types.Library{
					ID:      "bootstrap@5.0.2",
					Name:    "bootstrap",
					Version: "5.0.2",
					License: "MIT",
				},
				Dependencies: map[string]string{
					"js-tokens": "^4.0.0",
				},
				OptionalDependencies: map[string]string{
					"colors": "^1.4.0",
				},
				DevDependencies: map[string]string{
					"@babel/cli":  "^7.14.5",
					"@babel/core": "^7.14.6",
				},
				Workspaces: []string{
					"packages/*",
					"backend",
				},
			},
		},
		{
			name:      "happy path - legacy license",
			inputFile: "testdata/legacy_package.json",
			want: packagejson.Package{
				Library: types.Library{
					ID:      "angular@4.1.2",
					Name:    "angular",
					Version: "4.1.2",
					License: "ISC",
				},
				Dependencies: map[string]string{},
				DevDependencies: map[string]string{
					"@babel/cli":  "^7.14.5",
					"@babel/core": "^7.14.6",
				},
			},
		},
		{
			name:      "happy path - version doesn't exist",
			inputFile: "testdata/without_version_package.json",
			want: packagejson.Package{
				Library: types.Library{
					ID:   "",
					Name: "angular",
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/invalid_package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			wantErr: "JSON decode error",
		},
		{
			name:      "without name and version",
			inputFile: "testdata/without_name_and_version_package.json",
			want: packagejson.Package{
				Library: types.Library{
					License: "MIT",
				},
			},
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.name), func(t *testing.T) {
			f, err := os.Open(v.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got, err := packagejson.NewParser().Parse(f)
			if v.wantErr != "" {
				assert.ErrorContains(t, err, v.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, v.want, got)
		})
	}
}
