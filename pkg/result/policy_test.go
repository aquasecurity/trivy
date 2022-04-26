package result

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalPolicyStore(t *testing.T) {
	policyFiles := map[string][]byte{
		"good.rego": []byte(`
package trivy

default ignore = false

focused_packages := {"org.apache.logging.log4j:log4j-core"}

ignore_severities := {"LOW", "MEDIUM"}

ignore {
    input.PkgName != focused_packages[_]
}
`),
		"bad.rego": []byte(`
package trivy

invalid rego file
`),
	}
	tempDir := t.TempDir()
	for filename, content := range policyFiles {
		err := os.WriteFile(filepath.Join(tempDir, filename), content, 0600)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		policyFile    string
		expectedError string
	}{
		{
			name:          "Good rego file",
			policyFile:    filepath.Join(tempDir, "good.rego"),
			expectedError: "",
		},
		{
			name:          "Bad rego file",
			policyFile:    filepath.Join(tempDir, "bad.rego"),
			expectedError: "unable to prepare for eval: ",
		},
		{
			name:          "Non-existing rego file",
			policyFile:    filepath.Join(tempDir, "non-existing.rego"),
			expectedError: "unable to read policy file ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLocalPolicyStore(context.Background(), tt.policyFile)
			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError, tt.name)
			} else {
				assert.Nil(t, err, tt.expectedError, tt.name)
			}
		})
	}
}

func TestRemotePolicyStore(t *testing.T) {
	tsFactory := func(handlerFunc http.HandlerFunc) *httptest.Server {
		return httptest.NewServer(handlerFunc)
	}
	happyHandler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, policyURI) {
			result := []byte(`{"result": true}`)
			w.Header().Add("Content-Type", "application/json")
			_, err := w.Write(result)
			require.NoError(t, err)
		}
	}

	tests := []struct {
		name          string
		input         interface{}
		want          bool
		expectedError string
		nilCtx        bool
		cancelCtx     bool
		ts            *httptest.Server
	}{
		{
			name:          "invalid input data",
			input:         make(chan int),
			want:          false,
			expectedError: "unable to process policy input:",
		},
		{
			name:          "failure on creation of the new HTTP request",
			input:         []byte(`input data`),
			want:          false,
			expectedError: "unable to create new policy request:",
			nilCtx:        true,
		},
		{
			name:          "failure on sending the HTTP request",
			input:         []byte(`input data`),
			want:          false,
			expectedError: "unable to send query policy request:",
			cancelCtx:     true,
		},
		{
			name:          "failure on unexpected response status",
			input:         []byte(`input data`),
			want:          false,
			expectedError: "unable to get query result,",
			ts: tsFactory(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}),
		},
		{
			name:          "failure on invalid response data",
			input:         []byte(`input data`),
			want:          false,
			expectedError: "unable to unmarshal query response:",
			ts: tsFactory(func(w http.ResponseWriter, r *http.Request) {
			}),
		},
		{
			name:          "the final happy result",
			input:         []byte(`input data`),
			want:          true,
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				ctx         context.Context
				cancel      context.CancelFunc
				remoteStore PolicyStore
				err         error
			)

			if tt.ts == nil {
				tt.ts = tsFactory(happyHandler)
			}
			defer tt.ts.Close()
			remoteStore, err = NewRemotePolicyStore(tt.ts.URL)
			require.NoError(t, err)
			require.NotNil(t, remoteStore)

			if !tt.nilCtx {
				ctx, cancel = context.WithCancel(context.Background())
				defer cancel()
			}
			if tt.cancelCtx {
				cancel()
			}

			result, err := remoteStore.Evaluate(ctx, tt.input)
			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError, tt.name)
			} else {
				assert.Nil(t, err, tt.name)
			}
			assert.Equal(t, tt.want, result, tt.name)
		})
	}
}
