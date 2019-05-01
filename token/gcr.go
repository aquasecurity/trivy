package token

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
)

type GCR struct {
	Store store.GCRCredStore
	Auth  types.AuthConfig
}

func NewGCR(auth types.AuthConfig, credPath string) *GCR {
	if credPath != "" {
		return &GCR{
			Store: store.NewGCRCredStore(credPath),
			Auth:  auth,
		}
	}
	return &GCR{Auth: auth}
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
	fmt.Printf("%v, %v \n", credStore, userCfg)
	helper := credhelper.NewGCRCredentialHelper(credStore, userCfg)
	return helper.Get(g.Auth.ServerAddress)
}
