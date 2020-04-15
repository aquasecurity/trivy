package types

import (
	"time"

	"github.com/aquasecurity/fanal/types"
	"github.com/caarlos0/env/v6"
)

type DockerConfig struct {
	UserName string `env:"TRIVY_USERNAME"`
	Password string `env:"TRIVY_PASSWORD"`
	Insecure bool   `env:"TRIVY_INSECURE" envDefault:"false"`
	NonSSL   bool   `env:"TRIVY_NONSSL" envDefault:"false"`
}

func GetDockerOption(timeout time.Duration) (types.DockerOption, error) {
	cfg := DockerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return types.DockerOption{}, err
	}

	return types.DockerOption{
		UserName:              cfg.UserName,
		Password:              cfg.Password,
		Timeout:               timeout,
		InsecureSkipTLSVerify: cfg.Insecure,
		NonSSL:                cfg.NonSSL,
	}, nil
}
