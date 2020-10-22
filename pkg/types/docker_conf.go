package types

import (
	"time"

	"github.com/caarlos0/env/v6"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
)

// DockerConfig holds the config of Docker
type DockerConfig struct {
	UserName      string `env:"TRIVY_USERNAME"`
	Password      string `env:"TRIVY_PASSWORD"`
	RegistryToken string `env:"TRIVY_REGISTRY_TOKEN"`
	Insecure      bool   `env:"TRIVY_INSECURE" envDefault:"false"`
	NonSSL        bool   `env:"TRIVY_NON_SSL" envDefault:"false"`
}

// GetDockerOption returns the Docker scanning options using DockerConfig
func GetDockerOption(timeout time.Duration) (types.DockerOption, error) {
	cfg := DockerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return types.DockerOption{}, xerrors.Errorf("unable to parse environment variables: %w", err)
	}

	return types.DockerOption{
		UserName:              cfg.UserName,
		Password:              cfg.Password,
		RegistryToken:         cfg.RegistryToken,
		Timeout:               timeout,
		InsecureSkipTLSVerify: cfg.Insecure,
		NonSSL:                cfg.NonSSL,
	}, nil
}
