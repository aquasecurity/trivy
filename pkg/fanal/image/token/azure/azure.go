package azure

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Registry struct {
	domain string
}

const azureURL = "azurecr.io"

func (r *Registry) CheckOptions(domain string, _ types.DockerOption) error {
	if !strings.HasSuffix(domain, azureURL) {
		return xerrors.Errorf("Azure registry: %w", types.InvalidURLPattern)
	}
	r.domain = domain
	return nil
}

func (r *Registry) GetCredential(ctx context.Context) (string, string, error) {
	credStore, err := NewACRCredStore()
	if err != nil {
		return "", "", xerrors.Errorf("ACR credential error: %w", err)
	}
	token, err := credStore.Get(ctx, r.domain)
	if err != nil {
		return "", "", xerrors.Errorf("unable to get a token: %w", err)
	}
	return "00000000-0000-0000-0000-000000000000", *token, err
}
