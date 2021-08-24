package python

import (
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	hook.RegisterHook(pythonHook{})
}

const version = 1

type pythonHook struct{}

// Hook merges all python packages installed by pip into one
func (h pythonHook) Hook(blob *types.BlobInfo) error {
	var apps []types.Application
	pythonApp := types.Application{
		Type: types.PythonPkg,
	}
	for _, app := range blob.Applications {
		if app.Type != types.PythonPkg {
			apps = append(apps, app)
			continue
		}
		pythonApp.Libraries = append(pythonApp.Libraries, app.Libraries...)
	}

	if len(pythonApp.Libraries) == 0 {
		return nil
	}

	// Overwrite Applications
	apps = append(apps, pythonApp)
	blob.Applications = apps

	return nil
}

func (h pythonHook) Version() int {
	return version
}

func (h pythonHook) Type() hook.Type {
	return hook.PythonPkg
}
