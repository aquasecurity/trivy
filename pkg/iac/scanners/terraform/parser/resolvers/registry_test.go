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

func Test_registryResolver_modulesEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		discovery http.HandlerFunc
		want      string // relative to the test server URL; empty means the /v1/modules/ fallback
	}{
		{
			name: "relative modules.v1 path (Terraform Cloud shape)",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"modules.v1":"/api/registry/v1/modules/"}`))
			},
			want: "/api/registry/v1/modules/",
		},
		{
			name: "relative path without trailing slash",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"modules.v1":"/registry/modules"}`))
			},
			want: "/registry/modules/",
		},
		{
			name: "no discovery document",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
		{
			name: "document without modules.v1",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"providers.v1":"/v1/providers/"}`))
			},
		},
		{
			name: "malformed document",
			discovery: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`not json`))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(serviceDiscoveryPath, tt.discovery)
			ts := httptest.NewTLSServer(mux)
			defer ts.Close()
			hostname := strings.TrimPrefix(ts.URL, "https://")

			want := ts.URL + defaultModulesPath
			if tt.want != "" {
				want = ts.URL + tt.want
			}

			r := &registryResolver{}
			got := r.modulesEndpoint(t.Context(), ts.Client(), hostname, log.WithPrefix("test"))
			assert.Equal(t, want, got)
		})
	}
}

func Test_registryResolver_modulesEndpoint_AbsoluteURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(serviceDiscoveryPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"modules.v1":"https://modules.example.com/v1/"}`))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	r := &registryResolver{}
	got := r.modulesEndpoint(t.Context(), ts.Client(), strings.TrimPrefix(ts.URL, "https://"), log.WithPrefix("test"))
	assert.Equal(t, "https://modules.example.com/v1/", got)
}

func Test_registryResolver_modulesEndpoint_CachesPerHost(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc(serviceDiscoveryPath, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"modules.v1":"/api/registry/v1/modules/"}`))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	hostname := strings.TrimPrefix(ts.URL, "https://")

	r := &registryResolver{}
	first := r.modulesEndpoint(t.Context(), ts.Client(), hostname, log.WithPrefix("test"))
	second := r.modulesEndpoint(t.Context(), ts.Client(), hostname, log.WithPrefix("test"))
	assert.Equal(t, first, second)
	assert.Equal(t, 1, calls)
}
