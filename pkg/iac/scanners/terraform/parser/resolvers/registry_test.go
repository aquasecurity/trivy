package resolvers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

func Test_getPrivateRegistryTokenFromEnvVars_ErrorsWithNoEnvVarSet(t *testing.T) {
	token, err := getPrivateRegistryTokenFromEnvVars("registry.example.com")
	assert.Empty(t, token)
	assert.Equal(t, "no token was found for the registry at registry.example.com", err.Error())
}

func Test_getPrivateRegistryTokenFromEnvVars_ConvertsSiteNameToEnvVar(t *testing.T) {
	tests := []struct {
		name      string
		siteName  string
		tokenName string
	}{
		{
			name:      "returns string when simple env var set",
			siteName:  "registry.example.com",
			tokenName: "TF_TOKEN_registry_example_com",
		},
		{
			name:      "allows dashes in hostname to be dashes",
			siteName:  "my-registry.example.com",
			tokenName: "TF_TOKEN_my-registry_example_com",
		},
		{
			name:      "allows dashes in hostname to be double underscores",
			siteName:  "my-registry.example.com",
			tokenName: "TF_TOKEN_my__registry_example_com",
		},
		{
			name:      "handles utf8 to punycode correctly",
			siteName:  "例えば.com",
			tokenName: "TF_TOKEN_xn--r8j3dr99h_com",
		},
		{
			name:      "handles punycode with dash to underscore conversion",
			siteName:  "café.fr",
			tokenName: "TF_TOKEN_xn____caf__dma_fr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.tokenName, "abcd")
			token, err := getPrivateRegistryTokenFromEnvVars(tt.siteName)
			assert.Equal(t, "abcd", token)
			require.NoError(t, err)
		})
	}
}

func Test_resolveVersion(t *testing.T) {
	makeModuleVersions := func(versions ...string) moduleVersions {
		return moduleVersions{
			Modules: []moduleProviderVersions{
				{Versions: xslices.Map(versions, func(v string) moduleVersion {
					return moduleVersion{Version: v}
				})},
			},
		}
	}

	tests := []struct {
		name     string
		input    string
		versions moduleVersions
		want     string
		wantErr  string
	}{
		{
			name:     "pessimistic constraint ~> 3.1",
			input:    "~> 3.1",
			versions: makeModuleVersions("3.0.0", "3.1.0", "3.2.0", "4.0.0"),
			want:     "3.2.0",
		},
		{
			name:     "exact version = 3.1.0",
			input:    "= 3.1.0",
			versions: makeModuleVersions("3.0.0", "3.1.0", "3.1.1"),
			want:     "3.1.0",
		},
		{
			name:     "empty constraint returns error",
			input:    "",
			versions: makeModuleVersions("1.0.0", "2.0.0", "3.0.0"),
			wantErr:  "improper constraint",
		},
		{
			name:     "invalid constraint",
			input:    ">> 3.0",
			versions: makeModuleVersions("3.0.0", "3.1.0"),
			wantErr:  "improper constraint",
		},
		{
			name:     "no modules",
			input:    "~> 1.0",
			versions: moduleVersions{},
			wantErr:  "1 module expected, found 0",
		},
		{
			name:  "empty version list",
			input: "~> 1.0",
			versions: moduleVersions{
				Modules: []moduleProviderVersions{{Versions: nil}},
			},
			wantErr: "no available versions for module",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveVersion(tt.input, tt.versions)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func newDiscoveryServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, string) {
	mux := http.NewServeMux()
	mux.HandleFunc(serviceDiscoveryPath, h)
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts, strings.TrimPrefix(ts.URL, "https://")
}

func Test_registryResolver_modulesEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		status int // 0 means 200
		body   string
		want   string // absolute URL, or path under the test server; empty means defaultModulesPath
	}{
		{
			name: "relative modules.v1 path (Terraform Cloud shape)",
			body: `{"modules.v1":"/api/registry/v1/modules/"}`,
			want: "/api/registry/v1/modules/",
		},
		{
			name: "relative path without trailing slash",
			body: `{"modules.v1":"/registry/modules"}`,
			want: "/registry/modules/",
		},
		{
			name: "absolute URL",
			body: `{"modules.v1":"https://modules.example.com/v1/"}`,
			want: "https://modules.example.com/v1/",
		},
		{
			name:   "no discovery document",
			status: http.StatusNotFound,
		},
		{
			name: "document without modules.v1",
			body: `{"providers.v1":"/v1/providers/"}`,
		},
		{
			name: "malformed document",
			body: `not json`,
		},
		{
			name: "non-https modules.v1",
			body: `{"modules.v1":"http://modules.example.com/v1/"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, hostname := newDiscoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
				_, _ = w.Write([]byte(tt.body))
			})
			want := tt.want
			switch {
			case want == "":
				want = ts.URL + defaultModulesPath
			case !strings.HasPrefix(want, "https://"):
				want = ts.URL + want
			}
			r := &registryResolver{}
			assert.Equal(t, want, r.modulesEndpoint(t.Context(), ts.Client(), hostname, log.WithPrefix("test")))
		})
	}
}

func Test_registryResolver_modulesEndpoint_CachesPerHost(t *testing.T) {
	var calls int
	ts, hostname := newDiscoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"modules.v1":"/api/registry/v1/modules/"}`))
	})
	r := &registryResolver{}
	first := r.modulesEndpoint(t.Context(), ts.Client(), hostname, log.WithPrefix("test"))
	second := r.modulesEndpoint(t.Context(), ts.Client(), hostname, log.WithPrefix("test"))
	assert.Equal(t, first, second)
	assert.Equal(t, 1, calls)
}

func Test_registryResolver_modulesEndpoint_RetriesUnreachableHost(t *testing.T) {
	ts, hostname := newDiscoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"modules.v1":"/api/registry/v1/modules/"}`))
	})
	r := &registryResolver{}
	ts.CloseClientConnections()
	ts.Close()
	assert.Equal(t, "https://"+hostname+defaultModulesPath,
		r.modulesEndpoint(t.Context(), ts.Client(), hostname, log.WithPrefix("test")))

	_, ok := r.modulesEndpoints.Load(hostname)
	assert.False(t, ok, "a transport failure must not be cached")
}
