package azure

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/xerrors"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/containerregistry/runtime/containerregistry"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

type ACRCredStore struct {
	settings        auth.EnvironmentSettings
	exchangeScheme  string
	refreshTimeout  time.Duration
	exchangeTimeout time.Duration
}

func NewACRCredStore() (*ACRCredStore, error) {
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil, xerrors.Errorf("failed to get settings from environment: %w", err)
	}

	return &ACRCredStore{
		settings:        settings,
		exchangeScheme:  "https",
		refreshTimeout:  45 * time.Second,
		exchangeTimeout: 15 * time.Second,
	}, nil
}

func (a *ACRCredStore) SetActiveDirectoryEndpoint(uri string) {
	a.settings.Environment.ActiveDirectoryEndpoint = uri
}

func (a *ACRCredStore) SetExchangeScheme(scheme string) {
	a.exchangeScheme = scheme
}

func (a *ACRCredStore) getServicePrincipalToken() (*adal.ServicePrincipalToken, error) {
	// 1.Client Credentials
	if c, err := a.settings.GetClientCredentials(); err == nil {
		oAuthConfig, err := adal.NewOAuthConfig(c.AADEndpoint, c.TenantID)
		if err != nil {
			return nil, xerrors.Errorf("OAuth config error: %w", err)
		}
		return adal.NewServicePrincipalToken(*oAuthConfig, c.ClientID, c.ClientSecret, c.Resource)
	}

	// 2. Client Certificate
	if _, err := a.settings.GetClientCertificate(); err == nil {
		return nil, xerrors.New("authentication method clientCertificate currently unsupported")
	}

	// 3. Username Password
	if _, err := a.settings.GetUsernamePassword(); err == nil {
		return nil, xerrors.New("authentication method username/password currently unsupported")
	}

	// 4. MSI
	config := a.settings.GetMSI()
	opts := adal.ManagedIdentityOptions{IdentityResourceID: config.ClientID}
	return adal.NewServicePrincipalTokenFromManagedIdentity(a.settings.Environment.ResourceManagerEndpoint, &opts)
}

func (a *ACRCredStore) getRegistryRefreshToken(ctx context.Context, registry string, sp *adal.ServicePrincipalToken) (*string, error) {
	token, repoClient, err := a.refresh(ctx, registry, sp)
	if err != nil {
		return nil, xerrors.Errorf("refresh error: %w", err)
	}

	return a.exchange(ctx, registry, token, repoClient)
}

func (a *ACRCredStore) refresh(ctx context.Context, registry string, sp *adal.ServicePrincipalToken) (
	adal.Token, containerregistry.RefreshTokensClient, error) {
	ctx, cancel := context.WithTimeout(ctx, a.refreshTimeout)
	defer cancel()

	err := sp.RefreshWithContext(ctx)
	if err != nil {
		return adal.Token{}, containerregistry.RefreshTokensClient{}, err
	}
	token := sp.Token()
	repoClient := containerregistry.NewRefreshTokensClient(fmt.Sprintf("%s://%s", a.exchangeScheme, registry))
	repoClient.Authorizer = autorest.NewBearerAuthorizer(sp)

	return token, repoClient, nil
}

func (a *ACRCredStore) exchange(ctx context.Context, registry string, token adal.Token,
	repoClient containerregistry.RefreshTokensClient) (*string, error) {
	tenantID := a.settings.Values[auth.TenantID]
	ctx, cancel := context.WithTimeout(ctx, a.exchangeTimeout)
	defer cancel()

	result, err := repoClient.GetFromExchange(ctx, "access_token", registry, tenantID, "", token.AccessToken)
	if err != nil {
		return nil, xerrors.Errorf("exchange error: %w", err)
	}

	return result.RefreshToken, nil
}

func (a *ACRCredStore) Get(ctx context.Context, registry string) (*string, error) {
	sp, err := a.getServicePrincipalToken()
	if err != nil {
		return nil, xerrors.Errorf("service principal token error: %w", err)
	}
	return a.getRegistryRefreshToken(ctx, registry, sp)
}
