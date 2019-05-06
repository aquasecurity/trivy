package redhatbase

import (
	"bufio"
	"bytes"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer/os"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func init() {
	analyzer.RegisterOSAnalyzer(&redhatOSAnalyzer{})
}

type redhatOSAnalyzer struct{}

var redhatRe = regexp.MustCompile(`(.*) release (\d[\d\.]*)`)

func (a redhatOSAnalyzer) Analyze(fileMap extractor.FileMap) (analyzer.OS, error) {
	if file, ok := fileMap["etc/centos-release"]; ok {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
			if len(result) != 3 {
				return analyzer.OS{}, errors.New("cent: Invalid centos-release")
			}

			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				return analyzer.OS{Family: os.CentOS, Name: result[2]}, nil
			}
		}
	}

	if file, ok := fileMap["etc/oracle-release"]; ok {
		scanner := bufio.NewScanner(bytes.NewBuffer(file))
		for scanner.Scan() {
			line := scanner.Text()
			result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
			if len(result) != 3 {
				return analyzer.OS{}, errors.New("oracle: Invalid oracle-release")
			}
			return analyzer.OS{Family: os.Oracle, Name: result[2]}, nil
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
				return analyzer.OS{}, errors.New("redhat: Invalid redhat-release")
			}

			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				return analyzer.OS{Family: os.CentOS, Name: result[2]}, nil
			case "oracle", "oracle linux", "oracle linux server":
				return analyzer.OS{Family: os.Oracle, Name: result[2]}, nil
			case "fedora", "fedora linux":
				return analyzer.OS{Family: os.Fedora, Name: result[2]}, nil
			default:
				return analyzer.OS{Family: os.RedHat, Name: result[2]}, nil
			}
		}
	}

	return analyzer.OS{}, xerrors.Errorf("redhatbase: %w", os.AnalyzeOSError)
}

func parseFedoraRelease(file []byte) (analyzer.OS, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(file))
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return analyzer.OS{}, errors.New("cent: Invalid fedora-release")
		}

		switch strings.ToLower(result[1]) {
		case "fedora", "fedora linux":
			return analyzer.OS{Family: os.Fedora, Name: result[2]}, nil
		}
	}
	return analyzer.OS{}, xerrors.Errorf("redhatbase: %w", os.AnalyzeOSError)
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
