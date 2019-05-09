package gcr

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/extractor/docker"

	"github.com/docker/docker/api/types"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
)

type GCR struct {
	Store store.GCRCredStore
	Auth  types.AuthConfig
}

const gcrURL = "gcr.io"

func init() {
	docker.RegisterRegistry(&GCR{})
}

func (g *GCR) CheckOptions(domain string, d docker.DockerOption) error {
	if !strings.HasSuffix(domain, gcrURL) {
		return xerrors.New("invalid GCR url pattern")
	}

	g.Auth = types.AuthConfig{}
	if d.GCRCredPath != "" {
		g.Store = store.NewGCRCredStore(d.GCRCredPath)
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
	return helper.Get(g.Auth.ServerAddress)
}
