package http_test

import (
	"bytes"
	"cmp"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

func TestTraceTransport_RoundTrip(t *testing.T) {
	// Disable colors for consistent testing
	t.Setenv("NO_COLOR", "1")

	tests := []struct {
		name            string
		method          string
		url             string
		headers         map[string]string
		body            io.Reader
		wantOutput      string
		responseStatus  int
		responseBody    string
		responseHeaders map[string]string
		wantError       error
	}{
		{
			name:   "traces GET request",
			method: "GET",
			url:    "http://example.com/test",
			headers: map[string]string{
				"Accept": "application/json",
			},
			wantOutput: `
--- HTTP REQUEST ---
GET /test HTTP/1.1
Host: example.com
User-Agent: test-agent/1.0
Accept: application/json
Accept-Encoding: gzip



--- HTTP RESPONSE ---
HTTP/1.1 200 OK
Content-Length: 0


`,
		},
		{
			name:   "redacts sensitive headers",
			method: "POST",
			url:    "http://api.example.com/auth?token=secret123",
			headers: map[string]string{
				"Authorization": "Bearer my-secret-token",
				"Content-Type":  "application/json",
			},
			body: strings.NewReader(`{"password": "secret-password"}`),
			wantOutput: `
--- HTTP REQUEST ---
POST /auth?token=%3Credacted%3E HTTP/1.1
Host: api.example.com
User-Agent: test-agent/1.0
Content-Length: 26
Authorization: <redacted>
Content-Type: application/json
Accept-Encoding: gzip

{"password": "<redacted>"}

--- HTTP RESPONSE ---
HTTP/1.1 200 OK
Content-Length: 0


`,
		},
		{
			name:           "traces error responses",
			method:         "GET",
			url:            "http://example.com/error",
			responseStatus: 404,
			responseBody:   "Not Found",
			wantOutput: `
--- HTTP REQUEST ---
GET /error HTTP/1.1
Host: example.com
User-Agent: test-agent/1.0
Accept-Encoding: gzip



--- HTTP RESPONSE ---
HTTP/1.1 404 Not Found
Content-Length: 9

Not Found
`,
		},
		{
			name:           "redacts sensitive response headers",
			method:         "GET",
			url:            "http://example.com/login",
			responseStatus: 200,
			responseHeaders: map[string]string{
				"Set-Cookie":   "session=abc123; HttpOnly",
				"Content-Type": "text/plain",
			},
			responseBody: "OK",
			wantOutput: `
--- HTTP REQUEST ---
GET /login HTTP/1.1
Host: example.com
User-Agent: test-agent/1.0
Accept-Encoding: gzip



--- HTTP RESPONSE ---
HTTP/1.1 200 OK
Content-Length: 2
Content-Type: text/plain
Set-Cookie: <redacted>

OK
`,
		},
		{
			name:   "handles binary content",
			method: "POST",
			url:    "http://example.com/upload",
			headers: map[string]string{
				"Content-Type": "application/octet-stream",
			},
			body: bytes.NewReader([]byte{
				0x00,
				0x01,
				0x02,
				0x03,
			}),
			wantOutput: `
--- HTTP REQUEST ---
POST /upload HTTP/1.1
Host: example.com
User-Agent: test-agent/1.0
Content-Length: 22
Content-Type: application/octet-stream
Accept-Encoding: gzip

<binary data redacted>

--- HTTP RESPONSE ---
HTTP/1.1 200 OK
Content-Length: 0


`,
		},
		{
			name:   "redacts private keys detected by scanner",
			method: "POST",
			url:    "http://api.company.com/keys",
			headers: map[string]string{
				"Content-Type": "text/plain",
			},
			body: strings.NewReader(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7WXkqw8EQOLGWVzsUJ7tAwVAV5zTW8V+O1KoZFpENWKDZlPU
VwEiQxaZq8pQJbm2O9zKlMSU7J6PZpuBvb8ZUhxWz9SLKmzqZjIqI4Vg5UUrUpOo
V9aVzqf8ZoMxLQGjCa8iGPp6r6qF5a+FGQ5z9b5x8y1dF3cJNmzGVqw6XlHzpQZJ
z7YwWJmQyOsQKSGQUfZMSgNQs4qT8dOZqYq9iOzGWt1s3Q6QZO4vA4iJoXl8MgU2
EyG0ZxO7zBqQGKzXzMKJQP4Z+4qQ9Q1iNiQsUz8PzQgU8MzfzMGDQCJOJQZzX1zK
EwQwQ7CQJQJ8qQMqJ9Q2MQMqJ8qQKJQZMQOKJQZ4zX1zKEwQwQ7CQJQJ8
-----END RSA PRIVATE KEY-----
Normal text here`),
			wantOutput: `
--- HTTP REQUEST ---
POST /keys HTTP/1.1
Host: api.company.com
User-Agent: test-agent/1.0
Content-Length: 144
Content-Type: text/plain
Accept-Encoding: gzip

-----BEGIN RSA PRIVATE KEY-----
<redacted>
<redacted>
<redacted>
<redacted>
<redacted>
<redacted>
-----END RSA PRIVATE KEY-----
Normal text here

--- HTTP RESPONSE ---
HTTP/1.1 200 OK
Content-Length: 0


`,
		},
		{
			name:   "handles transport errors",
			method: "GET",
			url:    "http://example.com/test",
			wantOutput: `
--- HTTP REQUEST ---
GET /test HTTP/1.1
Host: example.com

--- HTTP ERROR ---
http: use last response
`,
			wantError: http.ErrUseLastResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a buffer to capture output
			var output bytes.Buffer

			// Create request recorder
			var recorder *RequestRecorder
			switch {
			case tt.wantError != nil:
				recorder = NewRequestRecorder(WithError(tt.wantError))
			case tt.responseStatus != 0 || tt.responseBody != "" || len(tt.responseHeaders) > 0:
				status := cmp.Or(tt.responseStatus, http.StatusOK)
				mockResponse := &http.Response{
					StatusCode: status,
					Status:     http.StatusText(status),
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(tt.responseBody)),
				}
				for k, v := range tt.responseHeaders {
					mockResponse.Header.Set(k, v)
				}
				recorder = NewRequestRecorder(WithResponse(mockResponse))
			default:
				recorder = NewRequestRecorder()
			}

			// Create trace transport with output writer
			transport := xhttp.NewTraceTransport(recorder, xhttp.WithWriter(&output))
			// Wrap with user agent transport for consistent testing
			transport = xhttp.NewUserAgent(transport, "test-agent/1.0")

			// Create request
			req, err := http.NewRequest(tt.method, tt.url, tt.body)
			require.NoError(t, err)

			// Set headers
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Make request
			resp, err := transport.RoundTrip(req)
			if tt.wantError != nil {
				assert.Equal(t, tt.wantError, err)
				return
			}
			require.NoError(t, err)
			defer resp.Body.Close()

			// Normalize CRLF to LF for consistent testing
			got := strings.ReplaceAll(output.String(), "\r\n", "\n")
			assert.Equal(t, tt.wantOutput, got)

			// Verify request was recorded
			recorded := recorder.Request()
			require.NotNil(t, recorded)
			assert.Equal(t, tt.method, recorded.Method)
			assert.Equal(t, tt.url, recorded.URL.String())
		})
	}
}
