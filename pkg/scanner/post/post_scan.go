package post

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner interface {
	Name() string
	PostScan(ctx context.Context, results types.Results) (types.Results, error)
}

func RegisterPostScanner(s Scanner) {
	// Avoid duplication
	postScanners[s.Name()] = s
}

func UnregisterPostScanner(name string) {
	delete(postScanners, name)
}

var postScanners = map[string]Scanner{}

func Scan(ctx context.Context, results types.Results) (types.Results, error) {
	var err error
	for _, s := range postScanners {
		results, err = s.PostScan(ctx, results)
		if err != nil {
			return nil, xerrors.Errorf("%s post scan error: %w", s.Name(), err)
		}
	}
	return results, nil
}
