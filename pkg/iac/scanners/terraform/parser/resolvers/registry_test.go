package resolvers

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				{Versions: lo.Map(versions, func(v string, _ int) moduleVersion {
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
