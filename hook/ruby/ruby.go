package ruby

import (
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	hook.RegisterHook(rubyHook{})
}

const version = 1

type rubyHook struct{}

// Hook merges all rubygems detected by gemspecs
func (h rubyHook) Hook(blob *types.BlobInfo) error {
	var apps []types.Application
	gemspecApp := types.Application{
		Type: types.GemSpec,
	}
	for _, app := range blob.Applications {
		if app.Type != types.GemSpec {
			apps = append(apps, app)
			continue
		}
		gemspecApp.Libraries = append(gemspecApp.Libraries, app.Libraries...)
	}

	if len(gemspecApp.Libraries) == 0 {
		return nil
	}

	// Overwrite Applications
	apps = append(apps, gemspecApp)
	blob.Applications = apps

	return nil
}

func (h rubyHook) Version() int {
	return version
}

func (h rubyHook) Type() hook.Type {
	return hook.GemSpec
}
