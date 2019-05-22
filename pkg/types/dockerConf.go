package types

import (
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/knqyf263/fanal/types"
)

type DockerConfig struct {
	AuthURL      string        `env:"TRIVY_AUTH_URL"`
	UserName     string        `env:"TRIVY_USERNAME"`
	Password     string        `env:"TRIVY_PASSWORD"`
	GcpCredPath  string        `env:"TRIVY_GCP_CREDENTIAL"`
	AwsAccessKey string        `env:"TRIVY_AWS_ACCESS"`
	AwsSecretKey string        `env:"TRIVY_AWS_SECRET"`
	AwsRegion    string        `env:"TRIVY_AWS_REGION"`
	Timeout      time.Duration `env:"TRIVY_TIMEOUT_SEC" envDefault:"60s"`
	Insecure     bool          `env:"TRIVY_INSECURE" envDefault:"true"`
	NonSSL       bool          `env:"TRIVY_NON_SSL" envDefault:"false"`
}

func GetDockerOption() (types.DockerOption, error) {
	cfg := DockerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return types.DockerOption{}, nil
	}
	return types.DockerOption{
		AuthURL:      cfg.AuthURL,
		UserName:     cfg.UserName,
		Password:     cfg.Password,
		GcpCredPath:  cfg.GcpCredPath,
		AwsAccessKey: cfg.AwsAccessKey,
		AwsSecretKey: cfg.AwsSecretKey,
		AwsRegion:    cfg.AwsRegion,
		Timeout:      cfg.Timeout,
		Insecure:     cfg.Insecure,
		NonSSL:       cfg.NonSSL,
	}, nil
}
