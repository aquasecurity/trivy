package pyproject_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/python/pyproject"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    map[string]string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "happy path",
			file:    "testdata/happy.toml",
			want:    map[string]string{"flask": "^1.0", "python": "^3.9"},
			wantErr: assert.NoError,
		},
		{
			name:    "sad path",
			file:    "testdata/sad.toml",
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := &pyproject.Parser{}
			got, err := p.Parse(f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.file)) {
				return
			}
			assert.Equalf(t, tt.want, got, "Parse(%v)", tt.file)
		})
	}
}
