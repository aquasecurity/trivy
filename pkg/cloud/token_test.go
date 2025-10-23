package cloud

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
)

type mockApiServer struct {
	server *httptest.Server
}

func (m *mockApiServer) Start() {
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// handle access token request
		if r.URL.Path == accessTokenPath {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"token": "test-token"}`))
		}
		if r.URL.Path == "/configs/secrets/secret-config.yaml" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"content": {"key": "value"}}`))
		}
	}))
}

func (m *mockApiServer) Close() {
	m.server.Close()
}

func TestGetAccessToken(t *testing.T) {

	mockServer := &mockApiServer{}
	mockServer.Start()
	defer mockServer.Close()

	tests := []struct {
		name               string
		opts               flag.Options
		want               string
		expectedStatusCode int
		errorContains      string
	}{
		{
			name: "happy path",
			opts: flag.Options{
				CloudOptions: flag.CloudOptions{
					CloudToken: "valid-token",
					ApiURL:     mockServer.server.URL,
				},
			},
			want:               "test-token",
			expectedStatusCode: http.StatusCreated,
		},
		{
			name: "no API URL",
			opts: flag.Options{
				CloudOptions: flag.CloudOptions{
					CloudToken: "valid-token",
					ApiURL:     "",
				},
			},
			errorContains:      "no API URL provided for getting access token from Trivy Cloud",
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name: "invalid token",
			opts: flag.Options{
				CloudOptions: flag.CloudOptions{
					CloudToken: "invalid-token",
					ApiURL:     mockServer.server.URL,
				},
			},
			errorContains:      "failed to get access token: received status code 401",
			expectedStatusCode: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAccessToken(t.Context(), tt.opts)

			if tt.errorContains != "" {
				require.ErrorContains(t, err, tt.errorContains)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)

		})
	}
}
