package types

import (
	"strings"

	"github.com/caarlos0/env/v6"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// DockerConfig holds the config of Docker
type DockerConfig struct {
	UserName      string `env:"TRIVY_USERNAME"`
	Password      string `env:"TRIVY_PASSWORD"`
	RegistryToken string `env:"TRIVY_REGISTRY_TOKEN"`
	NonSSL        bool   `env:"TRIVY_NON_SSL" envDefault:"false"`
}

// GetDockerOption returns the Docker scanning options using DockerConfig
func GetDockerOption(insecureTlsSkip bool, Platform string) (types.DockerOption, error) {
	cfg := DockerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return types.DockerOption{}, xerrors.Errorf("unable to parse environment variables: %w", err)
	}
	credentials := make([]types.Credential, 0)
	users := strings.Split(cfg.UserName, ",")
	passwords := strings.Split(cfg.Password, ",")
	for index, user := range users {

		if len(user) > 0 && index < len(passwords) && len(passwords[index]) > 0 {
			credentials = append(credentials, types.Credential{
				UserName: strings.TrimSpace(user),
				Password: strings.TrimSpace(passwords[index]),
			})
		}
	}
	if len(credentials) == 0 {
		credentials = append(credentials, types.Credential{}) // no credential use-case
	}

	return types.DockerOption{
		UserName:              credentials[0].UserName, // for backward competability (can be removed later)
		Password:              credentials[0].Password, // for backward competability (can be removed later)
		Credentials:           credentials,
		RegistryToken:         cfg.RegistryToken,
		InsecureSkipTLSVerify: insecureTlsSkip,
		NonSSL:                cfg.NonSSL,
		Platform:              Platform,
	}, nil
}
