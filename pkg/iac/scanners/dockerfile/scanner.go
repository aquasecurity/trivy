package dockerfile

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/generic"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func NewScanner(opts ...options.ScannerOption) *generic.GenericScanner {
	return generic.NewScanner("Dockerfile", types.SourceDockerfile, generic.ParseFunc(parser.Parse), opts...)
}
