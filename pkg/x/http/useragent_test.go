package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

func TestUserAgentTransport_RoundTrip(t *testing.T) {
	tests := []struct {
		name            string
		userAgent       string
		existingHeaders map[string]string
		existingUA      string
		wantUA          string
		wantHeaders     map[string]string
	}{
		{
			name:      "default user agent",
			userAgent: "",
			wantUA:    "trivy/dev",
		},
		{
			name:      "custom user agent",
			userAgent: "custom-scanner/2.1",
			wantUA:    "custom-scanner/2.1",
		},
		{
			name:      "preserves existing headers",
			userAgent: "test-agent/1.0",
			existingHeaders: map[string]string{
				"Authorization": "Bearer token123",
				"Content-Type":  "application/json",
			},
			wantUA: "test-agent/1.0",
			wantHeaders: map[string]string{
				"Authorization": "Bearer token123",
				"Content-Type":  "application/json",
			},
		},
		{
			name:       "overwrites existing user agent",
			userAgent:  "new-agent/2.0",
			existingUA: "old-agent/1.0",
			wantUA:     "new-agent/2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check User-Agent
				gotUA := r.Header.Get("User-Agent")
				assert.Equal(t, tt.wantUA, gotUA)

				// Check other headers are preserved
				for key, wantValue := range tt.wantHeaders {
					gotValue := r.Header.Get(key)
					assert.Equal(t, wantValue, gotValue, "header %s", key)
				}

				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Create transport with user agent
			transport := xhttp.NewTransport(xhttp.Options{
				Insecure:  true,
				UserAgent: tt.userAgent,
			})

			client := &http.Client{Transport: transport}

			// Create request
			req, err := http.NewRequest(http.MethodGet, server.URL, http.NoBody)
			require.NoError(t, err)

			// Set existing headers
			for key, value := range tt.existingHeaders {
				req.Header.Set(key, value)
			}

			// Set existing User-Agent if specified
			if tt.existingUA != "" {
				req.Header.Set("User-Agent", tt.existingUA)
			}

			// Make request
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}
