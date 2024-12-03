package google

import (
	"context"
	"strings"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type GoogleRegistryClient struct {
	Store  store.GCRCredStore
	domain string
}

type Registry struct {
}

// Google container registry
const gcrURLDomain = "gcr.io"
const gcrURLSuffix = ".gcr.io"

// Google artifact registry
const garURLSuffix = "-docker.pkg.dev"

// Google mirror registry
const gmrURLDomain = "mirror.gcr.io"

func (g *Registry) CheckOptions(domain string, option types.RegistryOptions) (intf.RegistryClient, error) {
	// We assume there is no chance that `mirror.gcr.io` will require authentication.
	// So we need to skip `mirror.gcr.io` to avoid errors confusing users when downloading DB's.
	if domain == gmrURLDomain {
		return nil, xerrors.Errorf("mirror.gcr.io doesn't require authentication")
	}
	if domain != gcrURLDomain && !strings.HasSuffix(domain, gcrURLSuffix) && !strings.HasSuffix(domain, garURLSuffix) {
		return nil, xerrors.Errorf("Google registry: %w", types.InvalidURLPattern)
	}
	client := GoogleRegistryClient{domain: domain}
	if option.GCPCredPath != "" {
		client.Store = store.NewGCRCredStore(option.GCPCredPath)
	}
	return &client, nil
}

func (g *GoogleRegistryClient) GetCredential(_ context.Context) (username, password string, err error) {
	var credStore store.GCRCredStore
	if g.Store == nil {
		credStore, err = store.DefaultGCRCredStore()
		if err != nil {
			return "", "", xerrors.Errorf("failed to get GCRCredStore: %w", err)
		}
	} else {
		credStore = g.Store
	}
	userCfg, err := config.LoadUserConfig()
	if err != nil {
		return "", "", xerrors.Errorf("failed to load user config: %w", err)
	}
	helper := credhelper.NewGCRCredentialHelper(credStore, userCfg)
	return helper.Get(g.domain)
}
