package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ettle/strcase"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/magefile/mage/sh"
)

func fixtureContainerImages() error {
	const (
		testImages = "ghcr.io/aquasecurity/trivy-test-images"
		dir        = "integration/testdata/fixtures/images/"
	)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tags, err := crane.ListTags(testImages)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		fileName := tag + ".tar.gz"
		filePath := filepath.Join(dir, fileName)
		if exists(filePath) {
			continue
		}
		fmt.Printf("Downloading %s...\n", tag)
		imgName := fmt.Sprintf("%s:%s", testImages, tag)
		img, err := crane.Pull(imgName)
		if err != nil {
			return err
		}
		tarPath := strings.TrimSuffix(filePath, ".gz")
		if err = crane.Save(img, imgName, tarPath); err != nil {
			return err
		}
		if err = sh.Run("gzip", tarPath); err != nil {
			return err
		}
	}
	return nil
}

func fixtureVMImages() error {
	const (
		testVMImages    = "ghcr.io/aquasecurity/trivy-test-vm-images"
		titleAnnotation = "org.opencontainers.image.title"
		dir             = "integration/testdata/fixtures/vm-images/"
	)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tags, err := crane.ListTags(testVMImages)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		img, err := crane.Pull(fmt.Sprintf("%s:%s", testVMImages, tag))
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		layers, err := img.Layers()
		if err != nil {
			return err
		}

		for i, layer := range layers {
			fileName, ok := manifest.Layers[i].Annotations[titleAnnotation]
			if !ok {
				continue
			}
			filePath := filepath.Join(dir, fileName)
			if exists(filePath) {
				return nil
			}
			fmt.Printf("Downloading %s...\n", fileName)
			if err = saveLayer(layer, filePath); err != nil {
				return err
			}
		}
	}
	return nil
}

func saveLayer(layer v1.Layer, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	c, err := layer.Compressed()
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, c); err != nil {
		return err
	}
	return nil
}

type fixture struct {
	path    string
	genID   bool
	genDeps bool
}

type fixtureSet struct {
	output   string
	pkg      string
	fixtures []fixture
}

func fixturePackageData() error {
	fixtureSets := []fixtureSet{
		{
			output: "pkg/fanal/analyzer/pkg/rpm/fixtures_test.go",
			pkg:    "rpm",
			fixtures: []fixture{{
				path: "pkg/fanal/analyzer/pkg/rpm/testdata/valid",
			}, {
				path: "pkg/fanal/analyzer/pkg/rpm/testdata/valid_big",
			}, {
				path: "pkg/fanal/analyzer/pkg/rpm/testdata/valid_with_modularitylabel",
			}},
		}, {
			output: "pkg/fanal/artifact/vm/fixtures_test.go",
			pkg:    "vm_test",
			fixtures: []fixture{{
				path:    "pkg/fanal/artifact/vm/testdata/AmazonLinux2.img.gz",
				genID:   true,
				genDeps: true,
			}},
		}}

	for _, fixtureSet := range fixtureSets {
		generateFixtures(fixtureSet)
	}

	return nil
}

func generateFixtures(set fixtureSet) error {
	writer, err := os.Create(set.output)
	if err != nil {
		return err
	}
	defer writer.Close()

	fmt.Fprintf(writer, "package %s\n\n", set.pkg)
	fmt.Fprintf(writer, "import \"github.com/aquasecurity/trivy/pkg/fanal/types\"\n\n")

	for _, fixture := range set.fixtures {
		if err := generateFixture(fixture, writer); err != nil {
			return err
		}
	}

	return nil
}

func generateFixture(fixture fixture, writer io.Writer) error {
	imageName := "dokken/centos-stream-8"

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	var packageFile string
	if strings.HasSuffix(fixture.path, ".gz") {
		diskFile := strings.TrimSuffix(fixture.path, ".gz")
		_, err := os.Stat(diskFile)
		if err != nil {
			if err := sh.Run("gunzip", "-f", "-k", fixture.path); err != nil {
				return err
			}
		}

		output, err := sh.Output("sudo", "kpartx", "-v", "-a", diskFile)
		if err != nil {
			return err
		}
		defer sh.Output("sudo", "kpartx", "-v", "-d", diskFile)

		tmpDir, err := os.MkdirTemp("", "fixtures")
		if err != nil {
			return err
		}

		outputLines := strings.Split(output, "\n")
		loopback := strings.Split(outputLines[len(outputLines)-1], " ")[2]

		if err := sh.Run("sudo", "mount", "/dev/mapper/"+loopback, tmpDir); err != nil {
			return err
		}

		if err := sh.Run("sudo", "cp", filepath.Join(tmpDir, "var", "lib", "rpm", "Packages"), "/tmp/Packages"); err != nil {
			return err
		}

		if err := sh.Run("sudo", "umount", tmpDir); err != nil {
			return err
		}

		if output, err = sh.Output("sudo", "kpartx", "-v", "-d", filepath.Join(wd, diskFile)); err != nil {
			return err
		}

		packageFile = "/tmp/Packages"
	} else {
		packageFile = filepath.Join(wd, fixture.path)
	}

	err = sh.Run("docker", "run", "-d", "--name", "gen_go_fixtures", "--rm", "-ti", "-v", packageFile+":/testdir/Packages", imageName)
	if err != nil {
		return err
	}

	defer sh.Run("docker", "rm", "-f", "gen_go_fixtures")

	queryFormat := `\{
		"name": "%{NAME}",
		"version": "%{VERSION}",
		"epoch": "%{RPMTAG_EPOCHNUM}",
		"release": "%{RELEASE}",
		"arch": "%{ARCH}",
		"vendor": "%{VENDOR}",
		"modularity_label": "%{RPMTAG_MODULARITYLABEL}",
		"licenses": ["%{LICENSE}"],
		"maintainer": "%{RPMTAG_VENDOR}",
		"installed_files": "[%{FILENAMES},]",
		"provides": "[%{RPMTAG_PROVIDENAME},]",
		"requires": "[%{RPMTAG_REQUIRENAME},]",
		"digest": "md5:%{SIGMD5}",
		"source_rpm": "%{SOURCERPM}"
	\}\n,`

	output, err := sh.Output("docker", "exec", "gen_go_fixtures",
		"rpm",
		"-qa",
		"--dbpath",
		"/testdir",
		"--queryformat",
		queryFormat)
	if err != nil {
		return err
	}

	output = "[" + strings.TrimRight(output, ", ") + "]"

	var packages []map[string]interface{}
	err = json.Unmarshal([]byte(output), &packages)
	if err != nil {
		return err
	}

	fmt.Fprintf(writer, "var required%sPackages = []types.Package{\n", strings.Title(strcase.ToCamel(filepath.Base(fixture.path))))

	if err := generatePackages(writer, packages, fixture.genID, fixture.genDeps); err != nil {
		return err
	}

	fmt.Fprintf(writer, "}\n\n")
	return nil
}

// splitFileName returns a name, version, release, epoch, arch:
//
//	e.g.
//		foo-1.0-1.i386.rpm => foo, 1.0, 1, i386
//		1:bar-9-123a.ia64.rpm => bar, 9, 123a, 1, ia64
//
// https://github.com/rpm-software-management/yum/blob/043e869b08126c1b24e392f809c9f6871344c60d/rpmUtils/miscutils.py#L301
func splitFileName(filename string) (name, ver, rel string, err error) {
	filename = strings.TrimSuffix(filename, ".rpm")

	archIndex := strings.LastIndex(filename, ".")
	if archIndex == -1 {
		return "", "", "", errors.New("no arch")
	}

	relIndex := strings.LastIndex(filename[:archIndex], "-")
	if relIndex == -1 {
		return "", "", "", errors.New("no release")
	}
	rel = filename[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(filename[:relIndex], "-")
	if verIndex == -1 {
		return "", "", "", errors.New("no version")
	}
	ver = filename[verIndex+1 : relIndex]

	name = filename[:verIndex]
	return name, ver, rel, nil
}

func toStringArray(s string) []string {
	return strings.Split(strings.TrimRight(s, ","), ",")
}

func toGoArray(array []string) string {
	s := "[]string{"
	for i, item := range array {
		if i > 0 {
			s += ", "
		}
		s += `"` + item + `"`
	}
	s += "}"
	return s
}

func getPackageID(pkg map[string]interface{}) string {
	return fmt.Sprintf("%s@%s-%s.%s", pkg["name"], pkg["version"], pkg["release"], pkg["arch"])
}

func nilOrGoArray(array []string) string {
	if len(array) == 0 || (len(array) == 1 && array[0] == "") {
		return "nil"
	} else {
		return toGoArray(array)
	}
}

func generateProvides(packages []map[string]interface{}) map[string]string {
	provides := make(map[string]string)
	for _, pkg := range packages {
		for _, provide := range toStringArray(pkg["provides"].(string)) {
			id := getPackageID(pkg)
			provides[provide] = id
		}
	}
	return provides
}

type Packages []map[string]interface{}

func (p Packages) Len() int           { return len(p) }
func (p Packages) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p Packages) Less(i, j int) bool { return p[i]["name"].(string) < p[j]["name"].(string) }

func generatePackages(writer io.Writer, packages Packages, genID, genDeps bool) error {
	sort.Sort(packages)

	provides := generateProvides(packages)

	for _, pkg := range packages {
		requires := make(map[string]bool)
		if genDeps {
			for _, dep := range toStringArray(pkg["requires"].(string)) {
				if p, found := provides[dep]; found && p != getPackageID(pkg) {
					requires[p] = true
				}
			}
		}
		sortedRequires := make([]string, 0, len(requires))
		for require, _ := range requires {
			sortedRequires = append(sortedRequires, require)
		}
		sort.Strings(sortedRequires)
		dependsOn := nilOrGoArray(sortedRequires)

		var sourceName, sourceVer, sourceRel string
		var err error
		if pkg["source_rpm"] != "(none)" {
			sourceName, sourceVer, sourceRel, err = splitFileName(pkg["source_rpm"].(string))
			if err != nil {
				return err
			}
		}

		arch := pkg["arch"]
		if arch == "(none)" {
			pkg["arch"] = ""
			arch = "None"
		} else {
			arch = pkg["arch"]
		}

		id := ""
		if genID {
			id = fmt.Sprintf("ID: \"%s\", ", getPackageID(pkg))
		}

		if pkg["maintainer"] == "(none)" {
			pkg["maintainer"] = ""
		}

		if pkg["digest"] == "md5:(none)" {
			pkg["digest"] = ""
		}

		if pkg["modularity_label"] == "(none)" {
			pkg["modularity_label"] = ""
		}

		if pkg["vendor"] == "(none)" {
			pkg["installed_files"] = ""
		}
		installedFiles := nilOrGoArray(toStringArray(pkg["installed_files"].(string)))

		fmt.Fprintf(writer, "\t{Name: \"%s\", "+
			"%s"+
			"Epoch: %s, "+
			"Version: \"%s\", "+
			"Release: \"%s\", "+
			"Arch: \"%s\", "+
			"Modularitylabel: \"%s\", "+
			"Licenses: []string{\"%s\"}, "+
			"Maintainer: \"%s\", "+
			"DependsOn: %s, "+
			"InstalledFiles: %s, "+
			"Digest: \"%s\", "+
			"SrcName: \"%s\", "+
			"SrcEpoch: %s, "+
			"SrcVersion: \"%s\", "+
			"SrcRelease: \"%s\"},\n",
			pkg["name"],
			id,
			pkg["epoch"],
			pkg["version"],
			pkg["release"],
			arch,
			pkg["modularity_label"],
			pkg["licenses"].(string),
			pkg["maintainer"],
			dependsOn,
			installedFiles,
			pkg["digest"],
			sourceName,
			pkg["epoch"],
			sourceVer,
			sourceRel)
	}

	return nil
}
