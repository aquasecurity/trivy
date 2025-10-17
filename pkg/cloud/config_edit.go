package cloud

import (
	"os"
	"os/exec"
	"runtime"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

// OpenConfigForEditing opens the Trivy Cloud config file for editing in the default editor specified in the EDITOR environment variable
func OpenConfigForEditing() error {
	configPath := getConfigPath()

	logger := log.WithPrefix(log.PrefixCloud)
	if !fsutils.FileExists(configPath) {
		logger.Debug("Trivy Cloud config file does not exist", log.String("config_path", configPath))
		defaultConfig.Save()
		configPath = getConfigPath()
	}

	editor := getEditCommand()

	cmd := exec.Command(editor, configPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func getEditCommand() string {
	editor := os.Getenv("EDITOR")
	if editor != "" {
		return editor
	}

	// fallback to notepad for windows or vi for macos/linux
	if runtime.GOOS == "windows" {
		return "notepad"
	}
	return "vi"
}
