package types

import (
	"strings"

	"github.com/caarlos0/env/v6"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// DockerConfig holds the config of Docker
type DockerConfig struct {
	UsersName     string `env:"TRIVY_USERNAME"`
	Passwords     string `env:"TRIVY_PASSWORD"`
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
	users := strings.Split(cfg.UsersName, ",")
	password := strings.Split(cfg.Passwords, ",")
	for index, user := range users {
		if len(user) > 0 && len(password[index]) > 0 {
			credentials = append(credentials, types.Credential{UserName: user, Password: password[index]})
		}
	}
	if len(credentials) == 0 {
		credentials = append(credentials, types.Credential{}) // no credential use-case
	}
	if len(credentials) > 1 {  // backward competability maybe can be removed later
		cfg.UsersName = credentials[0].UserName
		cfg.Passwords = credentials[0].Password
	}

	return types.DockerOption{
		UserName:              cfg.UsersName,
		Password:              cfg.Passwords,
		Credentials:           credentials,
		RegistryToken:         cfg.RegistryToken,
		InsecureSkipTLSVerify: insecureTlsSkip,
		NonSSL:                cfg.NonSSL,
		Platform:              Platform,
	}, nil
}
