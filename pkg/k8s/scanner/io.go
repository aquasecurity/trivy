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

func generateTempFileByArtifact(artifact *artifacts.Artifact, tempDir string) (string, error) {
	filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)
	if runtime.GOOS == "windows" {
		// removes characters not permitted in file/directory names on Windows
		filename = filenameWindowsFriendly(filename)
	}
	file, err := os.CreateTemp(tempDir, filename)
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

// generateTempDir creates a directory with yaml files generated from kubernetes artifacts
// returns a directory name, a map for mapping a temp target file to k8s artifact and error
func generateTempDir(arts []*artifacts.Artifact) (string, map[string]*artifacts.Artifact, error) {
	tempDir, err := os.MkdirTemp("", "trivyk8s*")
	if err != nil {
		return "", nil, xerrors.Errorf("failed to create temp directory: %w", err)
	}

	m := make(map[string]*artifacts.Artifact)
	for _, artifact := range arts {
		filename, err := generateTempFileByArtifact(artifact, tempDir)
		if err != nil {
			log.Error("Failed to create temp file", log.FilePath(filename), log.Err(err))
			continue
		}
		m[filename] = artifact
	}
	return tempDir, m, nil
}

func removeDir(dirname string) {
	if err := os.RemoveAll(dirname); err != nil {
		log.Error("Failed to remove temp directory", log.FilePath(dirname), log.Err(err))
	}
}

func removeFile(filename string) {
	if err := os.Remove(filename); err != nil {
		log.Error("Failed to remove temp file", log.FilePath(filename), log.Err(err))
	}
}

func filenameWindowsFriendly(name string) string {
	return r.ReplaceAllString(name, "_")
}
