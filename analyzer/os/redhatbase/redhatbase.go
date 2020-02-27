package redhatbase

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&redhatOSAnalyzer{})
}

type redhatOSAnalyzer struct{}

var redhatRe = regexp.MustCompile(`(.*) release (\d[\d\.]*)`)

func (a redhatOSAnalyzer) Analyze(fileMap extractor.FileMap) (types.OS, error) {
	if file, ok := fileMap["etc/centos-release"]; ok {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
			if len(result) != 3 {
				return types.OS{}, xerrors.New("cent: Invalid centos-release")
			}

			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				return types.OS{Family: os.CentOS, Name: result[2]}, nil
			}
		}
	}

	if file, ok := fileMap["etc/oracle-release"]; ok {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
			if len(result) != 3 {
				return types.OS{}, xerrors.New("oracle: Invalid oracle-release")
			}
			return types.OS{Family: os.Oracle, Name: result[2]}, nil
		}
	}

	if file, ok := fileMap["usr/lib/fedora-release"]; ok {
		return parseFedoraRelease(file)
	}

	if file, ok := fileMap["etc/fedora-release"]; ok {
		return parseFedoraRelease(file)
	}

	if file, ok := fileMap["etc/redhat-release"]; ok {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
			if len(result) != 3 {
				return types.OS{}, xerrors.New("redhat: Invalid redhat-release")
			}

			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				return types.OS{Family: os.CentOS, Name: result[2]}, nil
			case "oracle", "oracle linux", "oracle linux server":
				return types.OS{Family: os.Oracle, Name: result[2]}, nil
			case "fedora", "fedora linux":
				return types.OS{Family: os.Fedora, Name: result[2]}, nil
			default:
				return types.OS{Family: os.RedHat, Name: result[2]}, nil
			}
		}
	}

	return types.OS{}, xerrors.Errorf("redhatbase: %w", os.AnalyzeOSError)
}

func parseFedoraRelease(file []byte) (types.OS, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(file))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return types.OS{}, xerrors.New("cent: Invalid fedora-release")
		}

		switch strings.ToLower(result[1]) {
		case "fedora", "fedora linux":
			return types.OS{Family: os.Fedora, Name: result[2]}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("redhatbase: %w", os.AnalyzeOSError)
}

func (a redhatOSAnalyzer) RequiredFiles() []string {
	return []string{
		"etc/redhat-release",
		"etc/oracle-release",
		"etc/fedora-release",
		"usr/lib/fedora-release",
		"etc/centos-release",
	}
}
