package dockerfile

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/dockerfile"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/generic"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func NewScanner(opts ...options.ScannerOption) *generic.GenericScanner[*dockerfile.Dockerfile] {
	defaultOpts := []options.ScannerOption{
		generic.WithSupportsInlineIgnore[*dockerfile.Dockerfile](true),
	}
	p := generic.ParseFunc[*dockerfile.Dockerfile](parser.Parse)
	return generic.NewScanner("Dockerfile", types.SourceDockerfile, p, append(defaultOpts, opts...)...,
	)
}
