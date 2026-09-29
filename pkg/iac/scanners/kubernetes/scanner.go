package kubernetes

import (
	"context"
	"io"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/generic"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes/parser"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func NewScanner(opts ...options.ScannerOption) *generic.GenericScanner[*parser.Manifest] {
	p := generic.ParseFunc[*parser.Manifest](parse)
	return generic.NewScanner("Kubernetes", types.SourceKubernetes, p, opts...)
}

func parse(ctx context.Context, r io.Reader, path string) ([]*parser.Manifest, error) {
	return parser.Parse(ctx, r, path)
}
