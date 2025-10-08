package kubernetes

import (
	"context"
	"io"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/generic"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func NewScanner(opts ...options.ScannerOption) *generic.GenericScanner {
	return generic.NewScanner("Kubernetes", types.SourceKubernetes, generic.ParseFunc(parse), opts...)
}

func parse(ctx context.Context, r io.Reader, path string) (any, error) {
	return parser.Parse(ctx, r, path)
}
