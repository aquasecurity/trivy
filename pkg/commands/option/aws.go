package option

import (
	"github.com/urfave/cli/v2"
)

// AWSOption holds the options for AWS scanning
type AWSOption struct {
	Region      string
	Endpoint    string
	Services    []string
	UpdateCache bool
	ARN         string
	AccountID   string
}

// NewAWSOption is the factory method to return AWS options
func NewAWSOption(c *cli.Context) AWSOption {
	return AWSOption{
		Region:      c.String("region"),
		Endpoint:    c.String("endpoint"),
		Services:    c.StringSlice("service"),
		UpdateCache: c.Bool("update-cache"),
		AccountID:   c.String("account-id"),
		ARN:         c.String("arn"),
	}
}
