package downloader_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestDownloadWithETag(t *testing.T) {
	const (
		etag       = "test-etag"
		newContent = "new content"
	)

	// Test server that supports conditional requests:
	// - If-None-Match matches the current ETag -> 304 Not Modified
	// - otherwise -> 200 with fresh content and the current ETag
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, err := w.Write([]byte(newContent))
		assert.NoError(t, err)
	}))
	defer server.Close()

	tests := []struct {
		name        string
		cachedETag  string // ETag sent in the request (simulates the cached vexhub ETag)
		wantErr     error  // expected error (ErrSkipDownload on 304, nil otherwise)
		wantETag    string
		wantContent string
	}{
		{
			name:        "304 restores the cached files",
			cachedETag:  etag, // matches -> server replies 304
			wantErr:     downloader.ErrSkipDownload,
			wantETag:    "",               // no new ETag on skip
			wantContent: "cached content", // existing file is restored untouched
		},
		{
			name:        "stale ETag downloads new content and drops the backup",
			cachedETag:  "stale-etag", // no match -> server replies 200
			wantErr:     nil,
			wantETag:    etag,       // fresh ETag is returned
			wantContent: newContent, // file now holds the new content
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate an already-cached vexhub file
			dst := filepath.Join(t.TempDir(), "vex.json")
			require.NoError(t, os.WriteFile(dst, []byte("cached content"), 0o600))

			_ = xhttp.WithTransport(t.Context(), xhttp.NewTransport(xhttp.Options{Insecure: true}))

			newETag, err := downloader.Download(t.Context(), server.URL, dst, "", downloader.Options{
				Insecure: true,
				ETag:     tt.cachedETag,
			})

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantETag, newETag)

			// The file holds the expected content (restored on 304, replaced on 200)
			content, err := os.ReadFile(dst)
			require.NoError(t, err)
			assert.Equal(t, tt.wantContent, string(content))

			assert.NoFileExists(t, dst+".backup")
		})
	}
}
