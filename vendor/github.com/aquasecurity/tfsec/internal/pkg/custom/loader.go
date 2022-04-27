package custom

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/severity"
	"gopkg.in/yaml.v2"
)

type ChecksFile struct {
	Checks []*Check `json:"checks" yaml:"checks"`
}

func Load(customCheckDir string) error {
	_, err := os.Stat(customCheckDir)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	return loadCustomChecks(customCheckDir)
}

func loadCustomChecks(customCheckDir string) error {
	checkFiles, err := listFiles(customCheckDir, ".*_tfchecks.*")
	if err != nil {
		return err
	}
	var errorList []string
	for _, checkFilePath := range checkFiles {
		err = Validate(checkFilePath)
		if err != nil {
			errorList = append(errorList, err.Error())
			continue
		}
		checks, err := LoadCheckFile(checkFilePath)
		if err != nil {
			errorList = append(errorList, err.Error())
			continue
		}

		ProcessFoundChecks(checks)
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "\n"))
	}
	return nil
}

func LoadCheckFile(checkFilePath string) (ChecksFile, error) {
	var checks ChecksFile
	checkFileContent, err := ioutil.ReadFile(checkFilePath)
	if err != nil {
		return checks, err
	}
	ext := filepath.Ext(checkFilePath)
	switch strings.ToLower(ext) {
	case ".json":
		err = json.Unmarshal(checkFileContent, &checks)
		if err != nil {
			return checks, err
		}
	case ".yml", ".yaml":
		err = yaml.Unmarshal(checkFileContent, &checks)
		if err != nil {
			return checks, nil
		}
	default:
		return checks, fmt.Errorf("couldn't process the file %s", checkFilePath)
	}

	for _, check := range checks.Checks {
		check.Severity = severity.StringToSeverity(string(check.Severity))
	}
	return checks, nil
}

func listFiles(dir, pattern string) ([]string, error) {
	filteredFiles := []string{}
	err := filepath.Walk(dir,
		func(filePath string, file os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			matched, err := regexp.MatchString(pattern, file.Name())
			if err != nil {
				return err
			}
			if matched {
				filteredFiles = append(filteredFiles, filePath)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return filteredFiles, nil
}
