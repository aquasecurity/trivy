package nodejs

import (
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	hook.RegisterHook(systemFileFilterHook{})
}

const version = 1

type systemFileFilterHook struct{}

// Hook removes files installed by OS package manager such as yum.
func (h systemFileFilterHook) Hook(blob *types.BlobInfo) error {
	var apps []types.Application
	for _, app := range blob.Applications {
		// If the lang-specific package was installed by OS package manager, it should not be taken.
		// Otherwise, the package version will be wrong, then it will lead to false positive.
		if utils.StringInSlice("/"+app.FilePath, blob.SystemFiles) {
			continue
		}

		var libs []types.LibraryInfo
		for _, lib := range app.Libraries {
			// If the lang-specific package was installed by OS package manager, it should not be taken.
			// Otherwise, the package version will be wrong, then it will lead to false positive.
			if utils.StringInSlice("/"+lib.FilePath, blob.SystemFiles) {
				continue
			}
			libs = append(libs, lib)
		}

		// Overwrite Libraries
		app.Libraries = libs
		apps = append(apps, app)
	}

	// Overwrite Applications
	blob.Applications = apps

	// Remove system files since this field is necessary only in this hook.
	blob.SystemFiles = nil

	return nil
}

func (h systemFileFilterHook) Version() int {
	return version
}

func (h systemFileFilterHook) Type() hook.Type {
	return hook.SystemFileFilter
}
