package http

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		contains []string
		notContains []string
	}{
		{
			name: "redact authorization header",
			headers: http.Header{
				"Authorization": []string{"Bearer secret-token"},
				"Content-Type":  []string{mimeApplicationJSON},
			},
			contains: []string{"Content-Type: " + mimeApplicationJSON, redactedText},
			notContains: []string{"secret-token"},
		},
		{
			name: "redact multiple sensitive headers",
			headers: http.Header{
				"Cookie":       []string{"session=abc123"},
				"X-API-Key":    []string{"my-secret-key"},
				"Accept":       []string{"*/*"},
			},
			contains: []string{redactedText, "Accept: */*"},
			notContains: []string{"abc123", "my-secret-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.headers.Clone()
			redactHeaders(headers)
			
			// Check that sensitive values are redacted
			for _, header := range headers {
				for _, value := range header {
					for _, forbidden := range tt.notContains {
						assert.NotContains(t, value, forbidden)
					}
				}
			}
		})
	}
}

func TestRedactQueryParams(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		notContains []string
	}{
		{
			name:        "redact token parameter",
			url:         "https://api.example.com/path?token=secret123&foo=bar",
			notContains: []string{"secret123"},
		},
		{
			name:        "redact multiple sensitive parameters",
			url:         "https://api.example.com?api_key=key123&password=pass123&user=john",
			notContains: []string{"key123", "pass123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)
			
			redacted := redactQueryParams(u)
			
			for _, forbidden := range tt.notContains {
				assert.NotContains(t, redacted.String(), forbidden)
			}
		})
	}
}

func TestRedactBody(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		contentType string
		contains    []string
		notContains []string
	}{
		{
			name:        "redact JSON password field",
			body:        []byte(`{"username": "john", "password": "secret123"}`),
			contentType: mimeApplicationJSON,
			contains:    []string{`"username": "john"`, redactedText},
			notContains: []string{"secret123"},
		},
		{
			name:        "redact form data",
			body:        []byte(`username=john&password=secret123&api_key=mykey`),
			contentType: mimeApplicationFormURLEncoded,
			contains:    []string{"username=john", redactedText},
			notContains: []string{"secret123", "mykey"},
		},
		{
			name:        "binary content",
			body:        []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			contentType: mimeApplicationOctetStream,
			contains:    []string{binaryRedactText},
			notContains: []string{},
		},
		{
			name:        "preserve non-sensitive data",
			body:        []byte(`{"name": "John", "email": "john@example.com"}`),
			contentType: mimeApplicationJSON,
			contains:    []string{`"name": "John"`, `"email": "john@example.com"`},
			notContains: []string{redactedText},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redacted := redactBody(tt.body, tt.contentType)
			result := string(redacted)
			
			for _, expected := range tt.contains {
				assert.Contains(t, result, expected)
			}
			for _, forbidden := range tt.notContains {
				assert.NotContains(t, result, forbidden)
			}
		})
	}
}

func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{"octet-stream", mimeApplicationOctetStream, true},
		{"image", mimeImagePrefix + "png", true},
		{"json", mimeApplicationJSON, false},
		{"text", mimeTextPrefix + "plain", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinaryContent(tt.contentType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsBinaryData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"null bytes", []byte{0x00, 0x01, 0x02}, true},
		{"text data", []byte("Hello, World!"), false},
		{"empty data", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinaryData(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTraceTransport(t *testing.T) {
	// Create a test server
	server := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=test123")
		w.Header().Set("Content-Type", mimeApplicationJSON)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"api_key": "response-secret", "status": "ok"}`))
	})
	
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	
	// Create request
	req, err := http.NewRequest("POST", "http://example.com/test?token=secret", strings.NewReader(`{"password": "test123"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer my-token")
	req.Header.Set("Content-Type", mimeApplicationJSON)
	
	// Use RoundTripper with mock
	transport := NewTraceTransport(RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec.Result(), nil
	}))
	
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Restore stderr
	w.Close()
	os.Stderr = oldStderr
	
	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()
	
	// Verify request trace - secrets should be redacted
	assert.Contains(t, output, "--- HTTP REQUEST ---")
	assert.Contains(t, output, redactedText) // Authorization should be redacted
	assert.NotContains(t, output, "my-token") // Original token should not appear
	assert.NotContains(t, output, "test123") // Password should not appear
	assert.NotContains(t, output, "secret") // Query param should not appear
	
	// Verify response trace - secrets should be redacted
	assert.Contains(t, output, "--- HTTP RESPONSE ---")
	assert.NotContains(t, output, "response-secret") // API key should not appear
	assert.NotContains(t, output, "session=test123") // Cookie value should not appear
}

// RoundTripperFunc is an adapter to use a function as RoundTripper
type RoundTripperFunc func(*http.Request) (*http.Response, error)

func (f RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}