package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy/pkg/log"
)

var r = regexp.MustCompile("\\\\|/|:|\\*|\\?|<|>")

// generateTempFolder creates a folder with yaml files generated from kubernetes artifacts
// returns a folder name, a map for mapping a temp target file to k8s artifact and error
func generateTempFolder(arts []*artifacts.Artifact) (string, map[string]*artifacts.Artifact, error) {
	tempFolder, err := os.MkdirTemp("", "trivyk8s*")
	if err != nil {
		return "", nil, xerrors.Errorf("failed to create temp folder: %w", err)
	}

	m := map[string]*artifacts.Artifact{}
	for _, artifact := range arts {
		filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)
		if runtime.GOOS == "windows" {
			// removes characters not permitted in file/directory names on Windows
			filename = filenameWindowsFriendly(filename)
		}
		file, err := os.CreateTemp(tempFolder, filename)
		if err != nil {
			log.Error("Failed to create temp file", log.String("path", filename), log.Err(err))
			continue
		}
		if err := yaml.NewEncoder(file).Encode(artifact.RawResource); err != nil {
			removeFile(filename)
			log.Error("Failed marshaling resource to a temp file", log.String("path", filename), log.Err(err))
			continue
		}
		if err := file.Close(); err != nil {
			log.Error("Failed to close temp file", log.String("path", file.Name()), log.Err(err))
		}
		m[filepath.Base(file.Name())] = artifact
	}
	return tempFolder, m, nil
}

func removeFolder(foldername string) {
	if err := os.RemoveAll(foldername); err != nil {
		log.Error("Failed to remove temp folder", log.String("path", foldername), log.Err(err))
	}
}

func removeFile(filename string) {
	if err := os.Remove(filename); err != nil {
		log.Error("Failed to remove temp file", log.String("path", filename), log.Err(err))
	}
}

func filenameWindowsFriendly(name string) string {
	return r.ReplaceAllString(name, "_")
}
