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

var r = regexp.MustCompile("[\\\\/:*?<>]")

func generateTempFileByArtifact(artifact *artifacts.Artifact, tempFolder string) (string, error) {
	filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)
	if runtime.GOOS == "windows" {
		// removes characters not permitted in file/directory names on Windows
		filename = filenameWindowsFriendly(filename)
	}
	file, err := os.CreateTemp(tempFolder, filename)
	if err != nil {
		return "", xerrors.Errorf("failed to create temporary file: %w", err)
	}
	shouldRemove := false
	defer func() {
		if err := file.Close(); err != nil {
			log.Error("Failed to close temp file", log.FilePath(file.Name()), log.Err(err))
		}
		if shouldRemove {
			removeFile(file.Name())
		}
	}()
	if err := yaml.NewEncoder(file).Encode(artifact.RawResource); err != nil {
		shouldRemove = true
		return "", xerrors.Errorf("failed to encode artifact: %w", err)
	}
	return filepath.Base(file.Name()), nil
}

// generateTempFolder creates a folder with yaml files generated from kubernetes artifacts
// returns a folder name, a map for mapping a temp target file to k8s artifact and error
func generateTempFolder(arts []*artifacts.Artifact) (string, map[string]*artifacts.Artifact, error) {
	tempFolder, err := os.MkdirTemp("", "trivyk8s*")
	if err != nil {
		return "", nil, xerrors.Errorf("failed to create temp folder: %w", err)
	}

	m := make(map[string]*artifacts.Artifact)
	for _, artifact := range arts {
		filename, err := generateTempFileByArtifact(artifact, tempFolder)
		if err != nil {
			log.Error("Failed to create temp file", log.FilePath(filename), log.Err(err))
			continue
		}
		m[filename] = artifact
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
