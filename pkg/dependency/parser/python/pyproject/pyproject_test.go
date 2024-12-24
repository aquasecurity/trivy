package pyproject_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pyproject"
	"github.com/aquasecurity/trivy/pkg/set"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    pyproject.PyProject
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy path",
			file: "testdata/happy.toml",
			want: pyproject.PyProject{
				Tool: pyproject.Tool{
					Poetry: pyproject.Poetry{
						Dependencies: pyproject.Dependencies{
							Set: set.New[string]("flask", "python", "requests", "virtualenv"),
						},
						Groups: map[string]pyproject.Group{
							"dev": {
								Dependencies: pyproject.Dependencies{
									Set: set.New[string]("pytest"),
								},
							},
							"lint": {
								Dependencies: pyproject.Dependencies{
									Set: set.New[string]("ruff"),
								},
							},
						},
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
