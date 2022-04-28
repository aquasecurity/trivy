package option

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

// KubernetesOption holds the options for Kubernetes scanning
type KubernetesOption struct {
	Namespace string
}

// NewKubernetesOption is the factory method to return Kubernetes options
func NewKubernetesOption(c *cli.Context) KubernetesOption {
	return KubernetesOption{
		Namespace: c.String("namespace"),
	}
}

// Init initialize the CLI context for SBOM generation
func (c *KubernetesOption) Init(ctx *cli.Context, logger *zap.SugaredLogger) error {
	return nil
}
