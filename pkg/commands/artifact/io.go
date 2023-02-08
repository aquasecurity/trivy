package artifact

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/log"
)

const k8sDataFile = "k8s_data"
const K8sRegoDataSubFolder = "k8sData"

type K8s struct {
	K8s Data `json:"k8s"`
}

type Data struct {
	Version string `json:"version"`
}

func createTempK8sRegoDataFile(version string, regoDataFolder string) error {
	k8sData := K8s{Data{Version: version}}
	b, err := json.Marshal(&k8sData)
	if err != nil {
		return err
	}
	if _, err := os.Stat(regoDataFolder); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(regoDataFolder, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(regoDataFolder, fmt.Sprintf("%s-*.json", k8sDataFile)), b, 0600)
}

func removeK8sDataFolder(filename string) {
	if err := os.RemoveAll(filename); err != nil {
		log.Logger.Errorf("failed to remove temp file %s: %s:", filename, err)
	}
}

func getTempk8sRegoDataFolder() string {
	return filepath.Join(os.TempDir(), K8sRegoDataSubFolder)
}
