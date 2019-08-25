package types

import (
	"time"

	"github.com/aquasecurity/fanal/types"
	"github.com/caarlos0/env/v6"
)

type DockerConfig struct {
	AuthURL  string        `env:"TRIVY_AUTH_URL"`
	UserName string        `env:"TRIVY_USERNAME"`
	Password string        `env:"TRIVY_PASSWORD"`
	Timeout  time.Duration `env:"TRIVY_TIMEOUT_SEC" envDefault:"60s"`
	Insecure bool          `env:"TRIVY_INSECURE" envDefault:"true"`
	NonSSL   bool          `env:"TRIVY_NON_SSL" envDefault:"false"`
}

func GetDockerOption() (types.DockerOption, error) {
	cfg := DockerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return types.DockerOption{}, err
	}
	return types.DockerOption{
		AuthURL:  cfg.AuthURL,
		UserName: cfg.UserName,
		Password: cfg.Password,
		Timeout:  cfg.Timeout,
		Insecure: cfg.Insecure,
		NonSSL:   cfg.NonSSL,
	}, nil
}
