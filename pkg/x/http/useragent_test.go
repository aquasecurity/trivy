package http_test

import (
	"net/http"
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
			// Create a request recorder
			recorder := NewRequestRecorder()

			// Create transport with user agent
			transport := xhttp.NewUserAgent(recorder, tt.userAgent)

			// Create request
			req, err := http.NewRequest(http.MethodGet, "http://example.com/test", http.NoBody)
			require.NoError(t, err)

			// Set existing headers
			for key, value := range tt.existingHeaders {
				req.Header.Set(key, value)
			}

			// Set User-Agent
			req.Header.Set("User-Agent", tt.existingUA)

			// Make request
			resp, _ := transport.RoundTrip(req)
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}

			// Check the recorded request
			recorded := recorder.Request()
			require.NotNil(t, recorded)

			// Check User-Agent
			gotUA := recorded.UserAgent()
			assert.Equal(t, tt.wantUA, gotUA)

			// Check other headers are preserved
			for key, wantValue := range tt.wantHeaders {
				gotValue := recorded.Header.Get(key)
				assert.Equal(t, wantValue, gotValue, "header %s", key)
			}
		})
	}
}
