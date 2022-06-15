package scanner

import (
	"fmt"
	"os"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
)

func createTempFile(artifact *artifacts.Artifact) (string, error) {
	filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)

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
