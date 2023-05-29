package azure

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Registry struct {
	domain string
}

const azureURL = "azurecr.io"

func (r *Registry) CheckOptions(domain string, _ types.RegistryOptions) error {
	if !strings.HasSuffix(domain, azureURL) {
		return xerrors.Errorf("Azure registry: %w", types.InvalidURLPattern)
	}
	r.domain = domain
	return nil
}

func (r *Registry) GetCredential(ctx context.Context) (string, string, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", "", xerrors.Errorf("ACR credential error: %w", err)
	}
	accessToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{})
	if err != nil {
		return "", "", xerrors.Errorf("unable to get a token: %w", err)
	}
	return "00000000-0000-0000-0000-000000000000", accessToken.Token, err
}

