package registry

import (
	"context"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/azure"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/ecr"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/google"
	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/intf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	registries []intf.Registry
)

func init() {
	RegisterRegistry(&google.Registry{})
	RegisterRegistry(&ecr.ECR{})
	RegisterRegistry(&azure.Registry{})
}

func RegisterRegistry(registry intf.Registry) {
	registries = append(registries, registry)
}

func GetToken(ctx context.Context, domain string, opt types.RegistryOptions) (auth authn.Basic) {
	// check registry which particular to get credential
	for _, registry := range registries {
		client, err := registry.CheckOptions(domain, opt)
		if err != nil {
			continue
		}
		username, password, err := client.GetCredential(ctx)
		if err != nil {
			// only skip check registry if error occurred
			log.Debug("Credential error", log.Err(err))
			break
		}
		return authn.Basic{
			Username: username,
			Password: password,
		}
	}
	return authn.Basic{}
}
