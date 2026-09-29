package intf

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type RegistryClient interface {
	GetCredential(ctx context.Context) (string, string, error)
}

type Registry interface {
	CheckOptions(domain string, option types.RegistryOptions) (RegistryClient, error)
}
