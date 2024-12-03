package packaging_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []ftypes.Package
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
			want: []ftypes.Package{
				{
					Name:    "setuptools",
					Version: "51.3.3",
					Licenses: []string{
						"UNKNOWN",
					},
				},
			},
		},
		{
			name:  "egg PKG-INFO with description containing non-RFC 7230 bytes",
			input: "testdata/unidecode-egg-info.PKG-INFO",
			want: []ftypes.Package{
				{
					Name:    "Unidecode",
					Version: "0.4.1",
					Licenses: []string{
						"UNKNOWN",
					},
				},
			},
		},
		{
			name:  "egg-info",
			input: "testdata/distlib-0.3.1-py3.9.egg-info",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-distlib
			// cd /usr/lib/python3.9/site-packages/
			// cat distlib-0.3.1-py3.9.egg-info | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | \
			// tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			want: []ftypes.Package{
				{
					Name:    "distlib",
					Version: "0.3.1",
					Licenses: []string{
						"Python license",
					},
				},
			},
		},
		{
			name:  "wheel METADATA",
			input: "testdata/simple-0.1.0.METADATA",

			// finding relevant metadata files for tests
			// mkdir dist-infos
			// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
			// find dist-infos/ | grep -v METADATA | xargs rm -R

			// for single METADATA file with known name
			// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^Licenses: []string{" | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\"}, \""$2"\", \""$3"\"\}\n")}'
			want: []ftypes.Package{
				{
					Name:     "simple",
					Version:  "0.1.0",
					Licenses: nil,
				},
			},
		},
		{
			name: "wheel METADATA",

			// for single METADATA file with known name
			// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^Licenses: []string{" | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\"}, \""$2"\", \""$3"\"\}\n")}'
			input: "testdata/distlib-0.3.1.METADATA",
			want: []ftypes.Package{
				{
					Name:    "distlib",
					Version: "0.3.1",
					Licenses: []string{
						"Python Software Foundation License",
					},
				},
			},
		},
		{
			name: "wheel METADATA",
			// Input defines "Classifier: License" but it ends at "OSI Approved" which doesn't define any specific license, thus "License" field is added to results
			input: "testdata/asyncssh-2.14.2.METADATA",

			want: []ftypes.Package{
				{
					Name:    "asyncssh",
					Version: "2.14.2",
					Licenses: []string{
						"Eclipse Public License v2.0",
					},
				},
			},
		},
		{
			name: "wheel METADATA",
			// Input defines multiple "Classifier: License"
			input: "testdata/pyphen-0.14.0.METADATA",

			want: []ftypes.Package{
				{
					Name:    "pyphen",
					Version: "0.14.0",
					Licenses: []string{
						"GNU General Public License v2 or later (GPLv2+)",
						"GNU Lesser General Public License v2 or later (LGPLv2+)",
						"Mozilla Public License 1.1 (MPL 1.1)",
					},
				},
			},
		},
		{
			name:    "invalid",
			input:   "testdata/invalid.json",
			wantErr: true,
		},
		{
			name:  "with License-Expression field",
			input: "testdata/iniconfig-2.0.0.METADATA",
			want: []ftypes.Package{
				{
					Name:    "iniconfig",
					Version: "2.0.0",
					Licenses: []string{
						"MIT",
					},
				},
			},
		},
		{
			name:  "with an empty license field but with license in Classifier",
			input: "testdata/zipp-3.12.1.METADATA",
			want: []ftypes.Package{
				{
					Name:    "zipp",
					Version: "3.12.1",
					Licenses: []string{
						"MIT License",
					},
				},
			},
		},
		{
			name:  "without licenses, but with a license file (a license in Classifier was removed)",
			input: "testdata/networkx-3.0.METADATA",
			want: []ftypes.Package{
				{
					Name:    "networkx",
					Version: "3.0",
					Licenses: []string{
						"file://LICENSE.txt",
					},
				},
			},
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
