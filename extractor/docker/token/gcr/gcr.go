package gcr

import (
	"context"
	"strings"

	"github.com/knqyf263/fanal/types"

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
		return xerrors.New("invalid GCR url pattern")
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
			return "", "", err
		}
	} else {
		credStore = g.Store
	}
	userCfg, err := config.LoadUserConfig()
	if err != nil {
		return "", "", err
	}
	helper := credhelper.NewGCRCredentialHelper(credStore, userCfg)
	return helper.Get(g.domain)
}
