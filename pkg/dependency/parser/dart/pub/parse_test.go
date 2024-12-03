package pub_test

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/dart/pub"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name          string
		useMinVersion bool
		inputFile     string
		want          []ftypes.Package
		wantErr       assert.ErrorAssertionFunc
	}{
		{
			name:          "not use minimum version",
			useMinVersion: false,
			inputFile:     "testdata/happy.lock",
			want: []ftypes.Package{
				{
					ID:           "crypto@3.0.2",
					Name:         "crypto",
					Version:      "3.0.2",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "flutter_test@0.0.0",
					Name:         "flutter_test",
					Version:      "0.0.0",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "uuid@3.0.6",
					Name:         "uuid",
					Version:      "3.0.6",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:          "use minimum version",
			useMinVersion: true,
			inputFile:     "testdata/happy.lock",
			want: []ftypes.Package{
				{
					ID:           "crypto@3.0.2",
					Name:         "crypto",
					Version:      "3.0.2",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "flutter_test@3.3.0",
					Name:         "flutter_test",
					Version:      "3.3.0",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "uuid@3.0.6",
					Name:         "uuid",
					Version:      "3.0.6",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:      "empty path",
			inputFile: "testdata/empty.lock",
			wantErr:   assert.NoError,
		},
		{
			name:      "broken yaml",
			inputFile: "testdata/broken.lock",
			wantErr:   assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			gotPkgs, _, err := pub.NewParser(tt.useMinVersion).Parse(f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.inputFile)) {
				return
			}

			sort.Sort(ftypes.Packages(gotPkgs))
			assert.Equal(t, tt.want, gotPkgs)
		})
	}
}
