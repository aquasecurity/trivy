package hadron

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParseComponents(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantPkgs types.Packages
		wantErr  bool
	}{
		{
			name:  "happy path",
			input: "./testdata/components.json",
			wantPkgs: types.Packages{
				{ID: "acl@2.3.2", Name: "acl", Version: "2.3.2"},
				{ID: "busybox@1.37.0", Name: "busybox", Version: "1.37.0"},
				{ID: "curl@8.21.0", Name: "curl", Version: "8.21.0"},
				{ID: "kernel@7.1.1", Name: "kernel", Version: "7.1.1"},
				{ID: "musl@1.2.6", Name: "musl", Version: "1.2.6"},
				{ID: "openssl@3.6.3", Name: "openssl", Version: "3.6.3"},
				{ID: "zlib@1.3.2", Name: "zlib", Version: "1.3.2"},
			},
		},
		{
			name:    "malformed json",
			input:   "./testdata/invalid.json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := hadronAnalyzer{}
			f, err := os.Open(tt.input)
			require.NoError(t, err)
			defer f.Close()

			gotPkgs, err := a.parseComponents(f)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantPkgs, gotPkgs)
		})
	}
}

func TestParseComponents_SkipsEmptyEntries(t *testing.T) {
	// Entries with an empty name or version are skipped defensively.
	in := `{"openssl": "3.6.3", "": "1.0.0", "broken": ""}`
	a := hadronAnalyzer{}
	gotPkgs, err := a.parseComponents(strings.NewReader(in))
	require.NoError(t, err)
	assert.Equal(t, types.Packages{
		{ID: "openssl@3.6.3", Name: "openssl", Version: "3.6.3"},
	}, gotPkgs)
}

func TestRequired(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "components.json",
			filePath: "usr/lib/hadron/components.json",
			want:     true,
		},
		{
			name:     "unrelated file",
			filePath: "usr/lib/os-release",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := hadronAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}
