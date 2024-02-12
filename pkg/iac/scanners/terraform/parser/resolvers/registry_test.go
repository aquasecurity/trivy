package resolvers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getPrivateRegistryTokenFromEnvVars(t *testing.T) {
	t.Run("returns empty string when no env var set", func(t *testing.T) {
		token, err := getPrivateRegistryTokenFromEnvVars("registry.example.com")
		assert.Equal(t, "", token)
		assert.Equal(t, "No token was found for the registry at registry.example.com", err.Error())
	})

	t.Run("returns string when simple env var set", func(t *testing.T) {
		t.Setenv("TF_TOKEN_registry_example_com", "abcd")
		token, err := getPrivateRegistryTokenFromEnvVars("registry.example.com")
		assert.Equal(t, "abcd", token)
		assert.Equal(t, nil, err)
	})

	t.Run("allows dashes in hostname to be dashes", func(t *testing.T) {
		t.Setenv("TF_TOKEN_my-registry_example_com", "1111")
		token, err := getPrivateRegistryTokenFromEnvVars("my-registry.example.com")
		assert.Equal(t, "1111", token)
		assert.Equal(t, nil, err)
	})

	t.Run("allows dashes in hostname to be double underscores", func(t *testing.T) {
		t.Setenv("TF_TOKEN_my__registry_example_com", "1234")
		token, err := getPrivateRegistryTokenFromEnvVars("my-registry.example.com")
		assert.Equal(t, "1234", token)
		assert.Equal(t, nil, err)
	})

	t.Run("handles utf8 to punycode correctly", func(t *testing.T) {
		t.Setenv("TF_TOKEN_xn--r8j3dr99h_com", "9999")
		token, err := getPrivateRegistryTokenFromEnvVars("例えば.com")
		assert.Equal(t, "9999", token)
		assert.Equal(t, nil, err)
	})

	t.Run("handles punycode with dash to underscore conversion", func(t *testing.T) {
		t.Setenv("TF_TOKEN_xn____caf__dma_fr", "9875")
		token, err := getPrivateRegistryTokenFromEnvVars("café.fr")
		assert.Equal(t, "9875", token)
		assert.Equal(t, nil, err)
	})
}
