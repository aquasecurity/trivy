package option

import "github.com/urfave/cli/v2"

type OtherOption struct {
	Insecure bool
}

// NewOtherOption is the factory method to return other option
func NewOtherOption(c *cli.Context) OtherOption {
	return OtherOption{
		Insecure: c.Bool("insecure"),
	}
}
