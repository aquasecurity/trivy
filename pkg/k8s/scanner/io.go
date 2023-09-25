package scanner

import (
	"fmt"
	"os"
	"regexp"
	"runtime"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy/pkg/log"
)

func createTempFile(artifact *artifacts.Artifact) (string, error) {
	filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)

	if runtime.GOOS == "windows" {
		//removes characters not permitted in file/directory names on Windows
		filename = filenameWindowsFriendly(filename)
	}
	file, err := os.CreateTemp("", filename)
	if err != nil {
		return "", xerrors.Errorf("creating tmp file error: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Logger.Errorf("failed to close temp file %s: %s:", file.Name(), err)
		}
	}()

	if err := yaml.NewEncoder(file).Encode(artifact.RawResource); err != nil {
		removeFile(filename)
		return "", xerrors.Errorf("marshaling resource error: %w", err)
	}

	return file.Name(), nil
}

func removeFile(filename string) {
	if err := os.Remove(filename); err != nil {
		log.Logger.Errorf("failed to remove temp file %s: %s:", filename, err)
	}
}

var r, _ = regexp.Compile("\\\\|/|:|\\*|\\?|<|>")

func filenameWindowsFriendly(name string) string {
	return r.ReplaceAllString(name, "_")
}
