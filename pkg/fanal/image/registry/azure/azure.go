package azure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type RegistryClient struct {
	domain string
	scope  string
	cloud  cloud.Configuration
}

type Registry struct {
}

const (
	azureURL      = ".azurecr.io"
	chinaAzureURL = ".azurecr.cn"
	scope         = "https://management.azure.com/.default"
	chinaScope    = "https://management.chinacloudapi.cn/.default"
	scheme        = "https"
)

func (r *Registry) CheckOptions(domain string, _ types.RegistryOptions) (intf.RegistryClient, error) {
	if strings.HasSuffix(domain, azureURL) {
		return &RegistryClient{
			domain: domain,
			scope:  scope,
			cloud:  cloud.AzurePublic,
		}, nil
	} else if strings.HasSuffix(domain, chinaAzureURL) {
		return &RegistryClient{
			domain: domain,
			scope:  chinaScope,
			cloud:  cloud.AzureChina,
		}, nil
	}

	return nil, xerrors.Errorf("Azure registry: %w", types.InvalidURLPattern)
}

func (r *RegistryClient) GetCredential(ctx context.Context) (string, string, error) {
	opts := azcore.ClientOptions{Cloud: r.cloud}
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: opts})
	if err != nil {
		return "", "", xerrors.Errorf("unable to generate acr credential error: %w", err)
	}
	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{r.scope}})
	if err != nil {
		return "", "", xerrors.Errorf("unable to get an access token: %w", err)
	}
	rt, err := refreshToken(ctx, aadToken.Token, r.domain)
	if err != nil {
		return "", "", xerrors.Errorf("unable to refresh token: %w", err)
	}
	return "00000000-0000-0000-0000-000000000000", *rt.RefreshToken, err
}

func refreshToken(ctx context.Context, accessToken, domain string) (azcontainerregistry.ACRRefreshToken, error) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	if tenantID == "" {
		return azcontainerregistry.ACRRefreshToken{}, errors.New("missing environment variable AZURE_TENANT_ID")
	}

	client, err := azcontainerregistry.NewAuthenticationClient(fmt.Sprintf("%s://%s", scheme, domain), nil)
	if err != nil {
		return azcontainerregistry.ACRRefreshToken{}, xerrors.Errorf("create auth client: %w", err)
	}

	resp, err := client.ExchangeAADAccessTokenForACRRefreshToken(ctx,
		azcontainerregistry.PostContentSchemaGrantTypeAccessToken,
		domain,
		&azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
			AccessToken: lo.ToPtr(accessToken),
			Tenant:      lo.ToPtr(tenantID),
		},
	)
	if err != nil {
		return azcontainerregistry.ACRRefreshToken{}, xerrors.Errorf("exchange access token: %w", err)
	}

	return resp.ACRRefreshToken, nil
}
