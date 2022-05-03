package packaging_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/python/packaging"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []types.Library
		wantErr bool
	}{
		// listing dependencies based on METADATA/PKG-INFO files
		// docker run --name pipenv --rm -it python:3.7-alpine /bin/sh
		// pip install pipenv
		// find / -wholename "*(dist-info/METADATA|.egg-info/PKG-INFO)" | xargs -I {} sh -c 'cat {} | grep -e "^Name:" -e "^Version:" -e "^License:"' | tee METADATAS
		// cat METADATAS | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{for(i=1;i<=NF;i=i+3){printf "\{\""$i"\", \""$(i+1)"\", \""$(i+2)"\"\}\n"}}'

		{
			name:  "egg PKG-INFO",
			input: "testdata/setuptools-51.3.3-py3.8.egg-info.PKG-INFO",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-setuptools
			// cd /usr/lib/python3.9/site-packages/setuptools-52.0.0-py3.9.egg-info/
			// cat PKG-INFO | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | \
			// tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			want: []types.Library{{Name: "setuptools", Version: "51.3.3", License: "UNKNOWN"}},
		},
		{
			name:  "egg-info",
			input: "testdata/distlib-0.3.1-py3.9.egg-info",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-distlib
			// cd /usr/lib/python3.9/site-packages/
			// cat distlib-0.3.1-py3.9.egg-info | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | \
			// tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			want: []types.Library{{Name: "distlib", Version: "0.3.1", License: "Python license"}},
		},
		{
			name:  "wheel METADATA",
			input: "testdata/simple-0.1.0.METADATA",

			// finding relevant metadata files for tests
			// mkdir dist-infos
			// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
			// find dist-infos/ | grep -v METADATA | xargs rm -R

			// for single METADATA file with known name
			// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			want: []types.Library{{Name: "simple", Version: "0.1.0", License: ""}},
		},
		{
			name: "wheel METADATA",

			// for single METADATA file with known name
			// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			input: "testdata/distlib-0.3.1.METADATA",
			want:  []types.Library{{Name: "distlib", Version: "0.3.1", License: "Python license"}},
		},
		{
			name:    "invalid",
			input:   "testdata/invalid.json",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.input)
			require.NoError(t, err)

			got, _, err := packaging.NewParser().Parse(f)
			require.Equal(t, tt.wantErr, err != nil)

			assert.Equal(t, tt.want, got)
		})
	}
}
