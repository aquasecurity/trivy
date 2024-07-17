package core_deps

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		file    string // Test input file
		want    []ftypes.Package
		wantErr string
	}{
		{
			name: "happy path",
			file: "testdata/happy.deps.json",
			want: []ftypes.Package{
				{
					ID:      "Newtonsoft.Json/13.0.1",
					Name:    "Newtonsoft.Json",
					Version: "13.0.1",
					Locations: []ftypes.Location{
						{
							StartLine: 33,
							EndLine:   39,
						},
					},
				},
			},
		},
		{
			name: "happy path with skipped libs",
			file: "testdata/without-runtime.deps.json",
			want: []ftypes.Package{
				{
					ID:      "JsonDiffPatch/2.0.61",
					Name:    "JsonDiffPatch",
					Version: "2.0.61",
					Locations: []ftypes.Location{
						{
							StartLine: 66,
							EndLine:   72,
						},
					},
				},
				{
					ID:      "Libuv/1.9.1",
					Name:    "Libuv",
					Version: "1.9.1",
					Locations: []ftypes.Location{
						{
							StartLine: 73,
							EndLine:   79,
						},
					},
				},
				{
					ID:      "System.Collections.Immutable/1.3.0",
					Name:    "System.Collections.Immutable",
					Version: "1.3.0",
					Locations: []ftypes.Location{
						{
							StartLine: 101,
							EndLine:   107,
						},
					},
				},
			},
		},
		{
			name: "happy path without libs",
			file: "testdata/no-libraries.deps.json",
			want: nil,
		},
		{
			name:    "sad path",
			file:    "testdata/invalid.deps.json",
			wantErr: "failed to decode .deps.json file: EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)

				sort.Sort(ftypes.Packages(got))
				sort.Sort(ftypes.Packages(tt.want))

				assert.Equal(t, tt.want, got)
			}
		})
	}
}
