package pom

import (
	"fmt"
	"os"
	"strings"
)

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
}

func isProperty(version string) bool {
	if version != "" && strings.HasPrefix(version, "${") && strings.HasSuffix(version, "}") {
		return true
	}
	return false
}

func packageID(name, version string) string {
	return fmt.Sprintf("%s:%s", name, version)
}
