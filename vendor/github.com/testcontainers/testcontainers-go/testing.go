package testcontainers

import (
	"context"
	"testing"
)

// SkipIfProviderIsNotHealthy is a utility function capable of skipping tests
// if the provider is not healthy, or running at all.
// This is a function designed to be used in your test, when Docker is not mandatory for CI/CD.
// In this way tests that depend on testcontainers won't run if the provider is provisioned correctly.
func SkipIfProviderIsNotHealthy(t *testing.T) {
	ctx := context.Background()
	provider, err := ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker is not running. TestContainers can't perform is work without it: %s", err)
	}
	err = provider.Health(ctx)
	if err != nil {
		t.Skipf("Docker is not running. TestContainers can't perform is work without it: %s", err)
	}
}
