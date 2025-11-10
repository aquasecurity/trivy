package downloader_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/downloader"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

func TestDownload(t *testing.T) {
	// Set up a test server with a self-signed certificate
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("test content"))
		assert.NoError(t, err)
	}))
	defer server.Close()

	tests := []struct {
		name     string
		insecure bool
		wantErr  bool
	}{
		{
			"Secure (should fail)",
			false,
			true,
		},
		{
			"Insecure (should succeed)",
			true,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up the destination path
			dst := t.TempDir()

			// Configure the HTTP transport with the insecure option
			ctx := xhttp.WithTransport(t.Context(), xhttp.NewTransport(xhttp.Options{
				Insecure: tt.insecure,
			}))

			// Execute the download
			_, err := downloader.Download(ctx, server.URL, dst, "", downloader.Options{
				Insecure: tt.insecure,
			})

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check the content of the downloaded file
			content, err := os.ReadFile(dst)
			require.NoError(t, err)
			assert.Equal(t, "test content", string(content))
		})
	}
}
