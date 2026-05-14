package funcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "tilde only",
			input: "~",
			want:  home,
		},
		{
			name:  "tilde with forward slash path",
			input: "~/Documents/test.tf",
			want:  filepath.Join(home, "Documents/test.tf"),
		},
		{
			name:  "tilde with nested path",
			input: "~/a/b/c",
			want:  filepath.Join(home, "a/b/c"),
		},
		{
			name:  "absolute path unchanged",
			input: "/etc/passwd",
			want:  "/etc/passwd",
		},
		{
			name:  "relative path unchanged",
			input: "relative/path",
			want:  "relative/path",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "tilde in middle unchanged",
			input: "/foo/~/bar",
			want:  "/foo/~/bar",
		},
		{
			name:    "user-specific home dir is not supported",
			input:   "~username",
			wantErr: true,
		},
		{
			name:    "user-specific home dir with path is not supported",
			input:   "~foo/foo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandHome(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
