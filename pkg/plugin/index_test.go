package plugin_test

import (
	"bytes"
	"context"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestManager_Update(t *testing.T) {
	tempDir := t.TempDir()
	fsutils.SetCacheDir(tempDir)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`this is index`))
		require.NoError(t, err)
	}))
	t.Cleanup(ts.Close)

	manager := plugin.NewManager(plugin.WithIndexURL(ts.URL + "/index.yaml"))
	err := manager.Update(context.Background())
	require.NoError(t, err)

	indexPath := filepath.Join(tempDir, "plugin", "index.yaml")
	assert.FileExists(t, indexPath)

	b, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	assert.Equal(t, "this is index", string(b))
}

func TestManager_Search(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		dir     string
		want    string
		wantErr string
	}{
		{
			name: "all plugins",
			args: nil,
			dir:  "testdata",
			want: `NAME                 TYPE       DESCRIPTION                                                  MAINTAINER          
foo                  output     A foo plugin                                                 aquasecurity        
bar                  generic    A bar plugin                                                 aquasecurity        
test                 generic    A test plugin                                                aquasecurity        
`,
		},
		{
			name: "keyword",
			args: []string{"bar"},
			dir:  "testdata",
			want: `NAME                 TYPE       DESCRIPTION                                                  MAINTAINER          
bar                  generic    A bar plugin                                                 aquasecurity        
`,
		},
		{
			name:    "no index",
			args:    nil,
			dir:     "unknown",
			wantErr: "plugin index not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsutils.SetCacheDir(tt.dir)

			var got bytes.Buffer
			m := plugin.NewManager(plugin.WithWriter(&got))
			err := m.Search(context.Background(), tt.args)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
