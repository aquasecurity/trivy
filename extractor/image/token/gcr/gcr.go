package gcr

import (
	"context"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
)

type GCR struct {
	Store  store.GCRCredStore
	domain string
}

const gcrURL = "gcr.io"

func (g *GCR) CheckOptions(domain string, d types.DockerOption) error {
	if !strings.HasSuffix(domain, gcrURL) {
		return xerrors.Errorf("GCR : %w", types.InvalidURLPattern)
	}
	g.domain = domain
	if d.GcpCredPath != "" {
		g.Store = store.NewGCRCredStore(d.GcpCredPath)
	}
	return nil
}

func (g *GCR) GetCredential(ctx context.Context) (username, password string, err error) {
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
