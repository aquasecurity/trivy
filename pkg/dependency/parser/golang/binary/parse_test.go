package binary_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/binary"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	wantLibs := []types.Library{
		{
			Name:         "github.com/aquasecurity/test",
			Version:      "",
			Relationship: types.RelationshipRoot,
		},
		{
			Name:         "stdlib",
			Version:      "1.15.2",
			Relationship: types.RelationshipDirect,
		},
		{
			Name:    "github.com/aquasecurity/go-pep440-version",
			Version: "v0.0.0-20210121094942-22b2f8951d46",
		},
		{
			Name:    "github.com/aquasecurity/go-version",
			Version: "v0.0.0-20210121072130-637058cfe492",
		},
		{
			Name:    "golang.org/x/xerrors",
			Version: "v0.0.0-20200804184101-5ec99f83aff1",
		},
	}

	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "ELF",
			inputFile: "testdata/test.elf",
			want:      wantLibs,
		},
		{
			name:      "PE",
			inputFile: "testdata/test.exe",
			want:      wantLibs,
		},
		{
			name:      "Mach-O",
			inputFile: "testdata/test.macho",
			want:      wantLibs,
		},
		{
			name:      "with replace directive",
			inputFile: "testdata/replace.elf",
			want: []types.Library{
				{
					Name:         "github.com/ebati/trivy-mod-parse",
					Version:      "",
					Relationship: types.RelationshipRoot,
				},
				{
					Name:         "stdlib",
					Version:      "1.16.4",
					Relationship: types.RelationshipDirect,
				},
				{
					Name:    "github.com/davecgh/go-spew",
					Version: "v1.1.1",
				},
				{
					Name:    "github.com/go-sql-driver/mysql",
					Version: "v1.5.0",
				},
			},
		},
		{
			name:      "with semver main module version",
			inputFile: "testdata/semver-main-module-version.macho",
			want: []types.Library{
				{
					Name:         "go.etcd.io/bbolt",
					Version:      "v1.3.5",
					Relationship: types.RelationshipRoot,
				},
				{
					Name:         "stdlib",
					Version:      "1.20.6",
					Relationship: types.RelationshipDirect,
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/dummy",
			wantErr:   "unrecognized executable format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got, _, err := binary.NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
