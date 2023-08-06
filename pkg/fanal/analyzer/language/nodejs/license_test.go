package nodejs

import (
	"github.com/aquasecurity/trivy/pkg/mapfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
)

func Test_ParseLicenses(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    map[string][]string
		wantErr string
	}{
		{
			name: "happy",
			dir:  filepath.Join("testdata", "happy"),
			want: map[string][]string{
				"package-a@0.0.1": {"CC-BY-SA-4.0"},
				"package-b@0.0.1": {"MIT"},
				"package-c@0.0.1": {"BSD-3-Clause"},
				"package-d@0.0.1": {"BSD-3-Clause"},
				"package-e@0.0.1": {"(GPL-3.0 OR LGPL-3.0 OR MPL-1.1 OR SEE LICENSE IN LICENSE)"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenses := map[string][]string{}
			pkgJsonParser := packagejson.NewParser()

			fsys := mapfsFromDir(t, tt.dir)

			err := ParseLicenses(pkgJsonParser, 0.9, licenses)(fsys, ".")
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, licenses)
		})
	}
}

func mapfsFromDir(t *testing.T, dir string) fs.FS {

	fsys := mapfs.New()

	walkDirFunc := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return fsys.MkdirAll(path, os.ModePerm)
		}

		return fsys.WriteFile(path, filepath.Join(dir, path))
	}

	err := fs.WalkDir(os.DirFS(dir), ".", walkDirFunc)
	require.NoError(t, err)

	return fsys
}

func Test_IsLicenseRefToFile(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantOk       bool
		wantFileName string
	}{
		{
			name:  "no ref to file",
			input: "MIT",
		},
		{
			name:         "empty input",
			wantOk:       true,
			wantFileName: "LICENSE",
		},
		{
			name:         "happy `SEE LICENSE IN`",
			input:        "SEE LICENSE IN LICENSE.md",
			wantOk:       true,
			wantFileName: "LICENSE.md",
		},
		{
			name:   "sad `SEE LICENSE IN`",
			input:  "SEE LICENSE IN ",
			wantOk: false,
		},
		{
			name:         "happy `LicenseRef-`",
			input:        "LicenseRef-LICENSE.txt",
			wantOk:       true,
			wantFileName: "LICENSE.txt",
		},
		{
			name:   "sad `LicenseRef-`",
			input:  "LicenseRef-",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, licenseFileName := IsLicenseRefToFile(tt.input)
			assert.Equal(t, ok, tt.wantOk)
			assert.Equal(t, licenseFileName, tt.wantFileName)
		})
	}
}
