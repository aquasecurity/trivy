package scanner

import (
	"fmt"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"os"
	"strings"

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

func createDynamicPolicyFolder(policyTemplate string, data string) (string, error) {
	uuid, err := uuid.NewUUID()
	if err != nil {
		return "", fmt.Errorf("failed to create %s temp dir", uuid)
	}
	filename := fmt.Sprintf("%s-*.rego", uuid)

	dir, err := ioutil.TempDir(".", "")
	if err != nil {
		return "", fmt.Errorf("failed to create %s temp dir", dir)
	}
	file, err := ioutil.TempFile(dir, filename)
	if err != nil {
		removeDir(dir)
		log.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Logger.Errorf("failed to close temp file %s: %s:", file.Name(), err)
		}
	}()
	policy := strings.ReplaceAll(policyTemplate, "$1", data)
	_, err = io.Copy(file, strings.NewReader(policy))
	if err != nil {
		removeDir(dir)
		return "", err
	}
	return dir, nil
}

func removeFile(filename string) {
	if err := os.Remove(filename); err != nil {
		log.Logger.Errorf("failed to remove temp file %s: %s:", filename, err)
	}
}

func removeDir(dirName string) {
	if err := os.RemoveAll(dirName); err != nil {
		log.Logger.Errorf("failed to remove temp dir %s: %s:", dirName, err)
	}
}
