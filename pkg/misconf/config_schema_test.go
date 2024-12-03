package misconf_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/misconf"
)

func Test_LoadConfigSchemas(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  int
	}{
		{
			name: "load one schema",
			paths: []string{
				filepath.Join("testdata", "schemas", "schema1.json"),
			},
			want: 1,
		},
		{
			name: "load dir with schemas",
			paths: []string{
				filepath.Join("testdata", "schemas"),
			},
			want: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := misconf.LoadConfigSchemas(tt.paths)
			require.NoError(t, err)
			assert.Len(t, got, tt.want)
		})
	}
}
