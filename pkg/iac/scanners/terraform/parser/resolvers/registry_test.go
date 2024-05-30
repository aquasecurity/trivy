package resolvers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getPrivateRegistryTokenFromEnvVars_ErrorsWithNoEnvVarSet(t *testing.T) {
	token, err := getPrivateRegistryTokenFromEnvVars("registry.example.com")
	assert.Equal(t, "", token)
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
