package rpmcmd

import (
	"bufio"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/fanal/extractor"
)

func init() {
	analyzer.RegisterPkgAnalyzer(&rpmCmdPkgAnalyzer{})
}

type rpmCmdPkgAnalyzer struct{}

func (a rpmCmdPkgAnalyzer) Analyze(fileMap extractor.FileMap) (pkgs []analyzer.Package, err error) {
	var parsedPkgs []analyzer.Package
	detected := false
	for _, filename := range a.RequiredFiles() {
		file, ok := fileMap[filename]
		if !ok {
			continue
		}
		parsedPkgs, err = a.parsePkgInfo(file)
		pkgs = append(pkgs, parsedPkgs...)
		detected = true
	}
	if !detected {
		return pkgs, errors.New("No package detected")
	}
	return pkgs, err
}

func (a rpmCmdPkgAnalyzer) parsePkgInfo(packageBytes []byte) (pkgs []analyzer.Package, err error) {
	tmpDir, err := ioutil.TempDir("", "rpm")
	defer os.RemoveAll(tmpDir)
	if err != nil {
		return nil, err
	}

	filename := filepath.Join(tmpDir, "Packages")
	err = ioutil.WriteFile(filename, packageBytes, 0700)
	if err != nil {
		return nil, err
	}

	// rpm-python 4.11.3 rpm-4.11.3-35.el7.src.rpm
	// Extract binary package names because RHSA refers to binary package names.
	out, err := outputPkgInfo(tmpDir)
	if err != nil {
		return nil, err
	}

	pkgString := string(out)

	scanner := bufio.NewScanner(strings.NewReader(pkgString))
	for scanner.Scan() {
		pkg, err := parseRPMOutput(scanner.Text())
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

func parseRPMOutput(line string) (pkg analyzer.Package, err error) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return pkg, xerrors.Errorf("Failed to parse package line: %s", line)
	}

	var epoch int
	epochStr := fields[1]
	if epochStr == "0" || epochStr == "(none)" {
		epoch = 0
	} else {
		epoch, err = strconv.Atoi(epochStr)
		if err != nil {
			return pkg, err
		}
	}

	return analyzer.Package{
		Name:    fields[0],
		Epoch:   epoch,
		Version: fields[2],
		Release: fields[3],
	}, nil
}

func outputPkgInfo(dir string) (out []byte, err error) {
	const old = "%{NAME} %{EPOCH} %{VERSION} %{RELEASE}\n"
	const new = "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE}\n"
	out, err = exec.Command("rpm", "--dbpath", dir, "-qa", "--qf", new).Output()
	if err != nil {
		return exec.Command("rpm", "--dbpath", dir, "-qa", "--qf", old).Output()
	}
	return out, nil
}

func (a rpmCmdPkgAnalyzer) RequiredFiles() []string {
	return []string{
		"usr/lib/sysimage/rpm/Packages",
		"var/lib/rpm/Packages",
	}
}
