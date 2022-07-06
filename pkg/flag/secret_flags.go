package flag

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const SecretConfigPathFlag = "secret-config"

type SecretFlags struct {
	SecretConfigPath *string
}

type SecretOptions struct {
	SecretConfigPath string
}

func NewSecretFlags() *SecretFlags {
	return &SecretFlags{
		SecretConfigPath: lo.ToPtr("trivy-secret.yaml"),
	}
}

func (f *SecretFlags) AddFlags(cmd *cobra.Command) {
	if f.SecretConfigPath != nil {
		cmd.Flags().String(SecretConfigPathFlag, *f.SecretConfigPath, "specify a path to config file for secret scanning")
	}
}

func (f *SecretFlags) ToOptions() SecretOptions {
	return SecretOptions{
		SecretConfigPath: viper.GetString(SecretConfigPathFlag),
	}
}
