package plugin_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/plugin"
)

func TestManager_Update(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tempDir)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`this is index`))
		assert.NoError(t, err)
	}))
	t.Cleanup(ts.Close)

	manager := plugin.NewManager(plugin.WithIndexURL(ts.URL + "/index.yaml"))
	err := manager.Update(context.Background(), plugin.Options{})
	require.NoError(t, err)

	indexPath := filepath.Join(tempDir, ".trivy", "plugins", "index.yaml")
	assert.FileExists(t, indexPath)

	b, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	assert.Equal(t, "this is index", string(b))
}

func TestManager_Search(t *testing.T) {
	tests := []struct {
		name    string
		keyword string
		dir     string
		want    string
		wantErr string
	}{
		{
			name:    "all plugins",
			keyword: "",
			dir:     "testdata",
			want: `NAME                 DESCRIPTION                                                  MAINTAINER           OUTPUT
foo                  A foo plugin                                                 aquasecurity           ✓
bar                  A bar plugin                                                 aquasecurity         
test_plugin          A test plugin                                                aquasecurity         
`,
		},
		{
			name:    "keyword",
			keyword: "bar",
			dir:     "testdata",
			want: `NAME                 DESCRIPTION                                                  MAINTAINER           OUTPUT
bar                  A bar plugin                                                 aquasecurity         
`,
		},
		{
			name:    "no index",
			keyword: "",
			dir:     "unknown",
			wantErr: "plugin index not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", tt.dir)

			var got bytes.Buffer
			m := plugin.NewManager(plugin.WithWriter(&got))
			err := m.Search(context.Background(), tt.keyword)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
