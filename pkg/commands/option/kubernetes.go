package option

import (
	"github.com/urfave/cli/v2"
)

// KubernetesOption holds the options for Kubernetes scanning
type KubernetesOption struct {
	Namespace    string
	ReportFormat string
}

// NewKubernetesOption is the factory method to return Kubernetes options
func NewKubernetesOption(c *cli.Context) KubernetesOption {
	return KubernetesOption{
		Namespace:    c.String("namespace"),
		ReportFormat: c.String("report"),
	}
}
