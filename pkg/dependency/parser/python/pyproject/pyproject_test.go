package pyproject_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pyproject"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    map[string]interface{}
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy path",
			file: "testdata/happy.toml",
			want: map[string]interface{}{
				"flask":  "^1.0",
				"python": "^3.9",
				"requests": map[string]interface{}{
					"version":  "2.28.1",
					"optional": true,
				},
				"virtualenv": []interface{}{
					map[string]interface{}{
						"version": "^20.4.3,!=20.4.5,!=20.4.6",
					},
					map[string]interface{}{
						"version": "<20.16.6",
						"markers": "sys_platform == 'win32' and python_version == '3.9'",
					},
				},
			},
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
