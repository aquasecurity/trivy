package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/rules"
)

func Test_loader_returns_expected_providers(t *testing.T) {
	providers := rules.GetProviderNames()
	assert.Len(t, providers, 11)
}

func Test_load_returns_expected_services(t *testing.T) {
	services := rules.GetProviderServiceNames("aws")
	assert.Len(t, services, 33)
}

func Test_load_returns_expected_service_checks(t *testing.T) {
	checks := rules.GetProviderServiceCheckNames("aws", "s3")
	assert.Len(t, checks, 11)
}

func Test_get_providers(t *testing.T) {
	dataset := rules.GetProviders()
	assert.Len(t, dataset, 11)
}

func Test_get_providers_as_Json(t *testing.T) {
	jsonData, err := rules.GetProvidersAsJson()
	require.NoError(t, err)

	assert.NotEmpty(t, jsonData)
}

func Test_get_provider_hierarchy(t *testing.T) {
	hierarchy := rules.GetProvidersHierarchy()

	var providers []string

	for provider := range hierarchy {
		providers = append(providers, provider)
	}

	assert.Len(t, providers, 11)
}
