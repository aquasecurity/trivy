package docker

import (
	"context"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/genuinetools/reg/repoutils"
	"github.com/aquasecurity/fanal/types"
)

var (
	registries []Registry
)

type Registry interface {
	CheckOptions(domain string, option types.DockerOption) error
	GetCredential(ctx context.Context) (string, string, error)
}

func RegisterRegistry(registry Registry) {
	registries = append(registries, registry)
}

func GetToken(ctx context.Context, domain string, opt types.DockerOption) (auth dockertypes.AuthConfig, err error) {
	authDomain := opt.AuthURL
	if authDomain == "" {
		authDomain = domain
	}
	auth.ServerAddress = authDomain
	// check registry which particular to get credential
	for _, registry := range registries {
		err := registry.CheckOptions(authDomain, opt)
		if err != nil {
			continue
		}
		auth.Username, auth.Password, err = registry.GetCredential(ctx)
		if err != nil {
			// only skip check registry if error occured
			break
		}
		return auth, nil
	}
	return repoutils.GetAuthConfig(opt.UserName, opt.Password, authDomain)
}
