package option

import (
	"github.com/urfave/cli/v2"
)

// SecretOption holds the options for secret scanning
type SecretOption struct {
	SecretConfigPath string
}

// NewSecretOption is the factory method to return secret options
func NewSecretOption(c *cli.Context) SecretOption {
	return SecretOption{
		SecretConfigPath: c.String("secret-config"),
	}
}
