package packagejson_test

import (
	"os"
	"path"
	"sort"
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
				Name:               "bootstrap",
				Version:            "5.0.2",
				License:            "MIT",
				ExternalReferences: []types.ExternalRef{{Type: types.RefWebsite, URL: "https://getbootstrap.com/"}, {Type: types.RefVCS, URL: "git+https://github.com/twbs/bootstrap.git"}, {Type: types.RefIssueTracker, URL: "https://github.com/twbs/bootstrap/issues"}},
			}},
			wantErr: "",
		},
		{
			name:      "happy path - legacy license",
			inputFile: "testdata/legacy_package.json",
			want: []types.Library{{
				Name:               "angular",
				Version:            "4.1.2",
				License:            "ISC",
				ExternalReferences: []types.ExternalRef{{Type: types.RefWebsite, URL: "https://getbootstrap.com/"}, {Type: types.RefVCS, URL: "git+https://github.com/twbs/bootstrap.git"}, {Type: types.RefIssueTracker, URL: "https://github.com/twbs/bootstrap/issues"}, {Type: types.RefLicense, URL: "https://opensource.org/licenses/ISC"}},
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

			for _, lib := range v.want {
				sortExternalRefs(lib.ExternalReferences)
			}

			for _, lib := range got {
				sortExternalRefs(lib.ExternalReferences)
			}

			require.NoError(t, err)
			assert.Equal(t, v.want, got)
		})
	}
}

func sortExternalRefs(refs []types.ExternalRef) {
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].URL < refs[j].URL
	})
}
