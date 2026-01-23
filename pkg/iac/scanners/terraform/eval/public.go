package eval

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

var defaultCacheDir = filepath.Join(os.TempDir(), ".aqua", "cache")

func Eval(ctx context.Context, fsys fs.FS, root string) (*GraphEvaluator, error) {
	if err := os.MkdirAll(defaultCacheDir, os.ModePerm); err != nil {
		return nil, err
	}

	modResolver := NewModuleResolver(defaultCacheDir, &packageFetcher{}, &registryClient{
		client: xhttp.ClientWithContext(ctx, xhttp.WithTimeout(5*time.Second)),
		logger: log.WithPrefix("registry-client"),
	})

	rootMod, err := modResolver.Resolve(context.TODO(), fsys, root)
	if err != nil {
		return nil, err
	}

	g := NewGraph()
	if err := g.Populate(rootMod); err != nil {
		return nil, err
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// TODO: pass a real workspace name
	e := NewEvaluator(g, rootMod, wd, "default")
	if err := e.EvalGraph(g); err != nil {
		return nil, err
	}
	return e, nil
}
