package walker

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedFile_Open(t *testing.T) {
	tests := []struct {
		name    string
		size    int64
		content string
		want    string
		wantErr string
	}{
		{
			name:    "size matches the content",
			size:    5,
			content: "hello",
			want:    "hello",
		},
		{
			name:    "empty file",
			size:    0,
			content: "",
			want:    "",
		},
		{
			name:    "reader ends before the declared size",
			size:    10,
			content: "hello",
			wantErr: "unable to read the file",
		},
		{
			name:    "large file is copied to a temp file",
			size:    defaultSizeThreshold,
			content: "hello",
			want:    "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := newCachedFile(tt.size, strings.NewReader(tt.content))
			t.Cleanup(func() {
				_ = cf.Clean()
			})

			r, err := cf.Open()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			defer r.Close()

			got, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
