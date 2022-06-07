package gomod

import (
	"context"
	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"path/filepath"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.GoModMergePostHandler, newGoModMergeHandler)
}

const version = 1

type gomodMergeHook struct{}

func newGoModMergeHandler(artifact.Option) (handler.PostHandler, error) {
	return gomodMergeHook{}, nil
}

// Handle merges go.mod and go.sum.
func (h gomodMergeHook) Handle(_ context.Context, _ *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	var apps []types.Application
	for _, app := range blob.Applications {
		if app.Type == types.GoModule {
			dir, file := filepath.Split(app.FilePath)

			// go.sum should be merged to go.mod.
			if file == types.GoSum {
				continue
			}

			if file == types.GoMod && lessThanGo117(app) {
				// e.g. /app/go.mod => /app/go.sum
				gosumFile := filepath.Join(dir, types.GoSum)
				if gosum := findGoSum(gosumFile, blob.Applications); gosum != nil {
					mergeGoSum(&app, gosum)
				}
			}
		}
		apps = append(apps, app)
	}

	// Overwrite Applications
	blob.Applications = apps

	return nil
}

func (h gomodMergeHook) Version() int {
	return version
}

func (h gomodMergeHook) Type() types.HandlerType {
	return types.GoModMergePostHandler
}

func (h gomodMergeHook) Priority() int {
	return types.GoModMergePostHandlerPriority
}

func findGoSum(path string, apps []types.Application) *types.Application {
	for _, app := range apps {
		if app.Type == types.GoModule && app.FilePath == path {
			return &app
		}
	}
	return nil
}

func lessThanGo117(gomod types.Application) bool {
	for _, lib := range gomod.Libraries {
		// The indirect field is populated only in Go 1.17+
		if lib.Indirect {
			return false
		}
	}
	return true
}

func mergeGoSum(gomod, gosum *types.Application) {
	uniq := map[string]types.Package{}
	for _, lib := range gomod.Libraries {
		// It will be used for merging go.sum.
		uniq[lib.Name] = lib
	}

	// For Go 1.16 or less, we need to merge go.sum into go.mod.
	for _, lib := range gosum.Libraries {
		// Skip dependencies in go.mod so that go.mod should be preferred.
		if _, ok := uniq[lib.Name]; ok {
			continue
		}

		// This dependency doesn't exist in go.mod, so it must be an indirect dependency.
		lib.Indirect = true
		uniq[lib.Name] = lib
	}

	gomod.Libraries = maps.Values(uniq)
}
