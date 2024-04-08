package pub_test

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/dart/pub"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantErr   assert.ErrorAssertionFunc
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			want: []types.Library{
				{
					ID:      "crypto@3.0.2",
					Name:    "crypto",
					Version: "3.0.2",
				},
				{
					ID:      "flutter_test@0.0.0",
					Name:    "flutter_test",
					Version: "0.0.0",
				},
				{
					ID:       "uuid@3.0.6",
					Name:     "uuid",
					Version:  "3.0.6",
					Indirect: true,
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

			gotLibs, _, err := pub.NewParser().Parse(f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.inputFile)) {
				return
			}

			sort.Slice(gotLibs, func(i, j int) bool {
				return gotLibs[i].ID < gotLibs[j].ID
			})

			assert.Equal(t, tt.want, gotLibs)
		})
	}
}
