package nodejs

import (
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
)

func init() {
	hook.RegisterHook(nodejsHook{})
}

const version = 1

type nodejsHook struct{}

// Hook merges all nodejs packages detected by package.json
func (h nodejsHook) Hook(blob *types.BlobInfo) error {
	var apps []types.Application
	nodeApp := types.Application{
		Type: types.NodePkg,
	}
	for _, app := range blob.Applications {
		if app.Type != types.NodePkg {
			apps = append(apps, app)
			continue
		}
		nodeApp.Libraries = append(nodeApp.Libraries, app.Libraries...)
	}

	if len(nodeApp.Libraries) == 0 {
		return nil
	}

	// Overwrite Applications
	apps = append(apps, nodeApp)
	blob.Applications = apps

	return nil
}

func (h nodejsHook) Version() int {
	return version
}

func (h nodejsHook) Type() hook.Type {
	return hook.PkgJson
}
