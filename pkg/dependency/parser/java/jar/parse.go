package jar

import (
	"archive/zip"
	"bufio"
	"crypto/sha1" // nolint:gosec
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	jarFileRegEx = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).jar$`)
)

type Client interface {
	Exists(groupID, artifactID string) (bool, error)
	SearchBySHA1(sha1 string) (Properties, error)
	SearchByArtifactID(artifactID, version string) (string, error)
}

type Parser struct {
	rootFilePath string
	offline      bool
	size         int64

	client Client
}

type Option func(*Parser)

func WithFilePath(filePath string) Option {
	return func(p *Parser) {
		p.rootFilePath = filePath
	}
}

func WithOffline(offline bool) Option {
	return func(p *Parser) {
		p.offline = offline
	}
}

func WithSize(size int64) Option {
	return func(p *Parser) {
		p.size = size
	}
}

func NewParser(c Client, opts ...Option) types.Parser {
	p := &Parser{
		client: c,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	libs, deps, err := p.parseArtifact(p.rootFilePath, p.size, r)
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to parse %s: %w", p.rootFilePath, err)
	}
	return removeLibraryDuplicates(libs), deps, nil
}

func (p *Parser) parseArtifact(filePath string, size int64, r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	log.Logger.Debugw("Parsing Java artifacts...", zap.String("file", filePath))

	// Try to extract artifactId and version from the file name
	// e.g. spring-core-5.3.4-SNAPSHOT.jar => sprint-core, 5.3.4-SNAPSHOT
	fileName := filepath.Base(filePath)
	fileProps := parseFileName(filePath)

	libs, m, foundPomProps, err := p.traverseZip(filePath, size, r, fileProps)
	if err != nil {
		return nil, nil, xerrors.Errorf("zip error: %w", err)
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	if foundPomProps {
		return libs, nil, nil
	}

	manifestProps := m.properties(filePath)
	if p.offline {
		// In offline mode, we will not check if the artifact information is correct.
		if !manifestProps.Valid() {
			log.Logger.Debugw("Unable to identify POM in offline mode", zap.String("file", fileName))
			return libs, nil, nil
		}
		return append(libs, manifestProps.Library()), nil, nil
	}

	if manifestProps.Valid() {
		// Even if MANIFEST.MF is found, the groupId and artifactId might not be valid.
		// We have to make sure that the artifact exists actually.
		if ok, _ := p.client.Exists(manifestProps.GroupID, manifestProps.ArtifactID); ok {
			// If groupId and artifactId are valid, they will be returned.
			return append(libs, manifestProps.Library()), nil, nil
		}
	}

	// If groupId and artifactId are not found, call Maven Central's search API with SHA-1 digest.
	props, err := p.searchBySHA1(r, filePath)
	if err == nil {
		return append(libs, props.Library()), nil, nil
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return nil, nil, xerrors.Errorf("failed to search by SHA1: %w", err)
	}

	log.Logger.Debugw("No such POM in the central repositories", zap.String("file", fileName))

	// Return when artifactId or version from the file name are empty
	if fileProps.ArtifactID == "" || fileProps.Version == "" {
		return libs, nil, nil
	}

	// Try to search groupId by artifactId via sonatype API
	// When some artifacts have the same groupIds, it might result in false detection.
	fileProps.GroupID, err = p.client.SearchByArtifactID(fileProps.ArtifactID, fileProps.Version)
	if err == nil {
		log.Logger.Debugw("POM was determined in a heuristic way", zap.String("file", fileName),
			zap.String("artifact", fileProps.String()))
		libs = append(libs, fileProps.Library())
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return nil, nil, xerrors.Errorf("failed to search by artifact id: %w", err)
	}

	return libs, nil, nil
}

func (p *Parser) traverseZip(filePath string, size int64, r xio.ReadSeekerAt, fileProps Properties) (
	[]types.Library, manifest, bool, error) {
	var libs []types.Library
	var m manifest
	var foundPomProps bool

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, manifest{}, false, xerrors.Errorf("zip error: %w", err)
	}

	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err := parsePomProperties(fileInJar, filePath)
			if err != nil {
				return nil, manifest{}, false, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			// Validation of props to avoid getting libs with empty Name/Version
			if props.Valid() {
				libs = append(libs, props.Library())

				// Check if the pom.properties is for the original JAR/WAR/EAR
				if fileProps.ArtifactID == props.ArtifactID && fileProps.Version == props.Version {
					foundPomProps = true
				}
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			m, err = parseManifest(fileInJar)
			if err != nil {
				return nil, manifest{}, false, xerrors.Errorf("failed to parse MANIFEST.MF: %w", err)
			}
		case isArtifact(fileInJar.Name):
			innerLibs, _, err := p.parseInnerJar(fileInJar, filePath) // TODO process inner deps
			if err != nil {
				log.Logger.Debugf("Failed to parse %s: %s", fileInJar.Name, err)
				continue
			}
			libs = append(libs, innerLibs...)
		}
	}
	return libs, m, foundPomProps, nil
}

func (p *Parser) parseInnerJar(zf *zip.File, rootPath string) ([]types.Library, []types.Dependency, error) {
	fr, err := zf.Open()
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to open %s: %w", zf.Name, err)
	}

	f, err := os.CreateTemp("", "inner")
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to create a temp file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()

	// Copy the file content to the temp file
	if n, err := io.CopyN(f, fr, int64(zf.UncompressedSize64)); err != nil {
		return nil, nil, xerrors.Errorf("file copy error: %w", err)
	} else if n != int64(zf.UncompressedSize64) {
		return nil, nil, xerrors.Errorf("file copy size error: %w", err)
	}

	// build full path to inner jar
	fullPath := path.Join(rootPath, zf.Name) // nolint:gosec
	if !strings.HasPrefix(fullPath, path.Clean(rootPath)) {
		return nil, nil, nil // zip slip
	}

	// Parse jar/war/ear recursively
	innerLibs, innerDeps, err := p.parseArtifact(fullPath, int64(zf.UncompressedSize64), f)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse %s: %w", zf.Name, err)
	}

	return innerLibs, innerDeps, nil
}

func (p *Parser) searchBySHA1(r io.ReadSeeker, filePath string) (Properties, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return Properties{}, xerrors.Errorf("file seek error: %w", err)
	}

	h := sha1.New() // nolint:gosec
	if _, err := io.Copy(h, r); err != nil {
		return Properties{}, xerrors.Errorf("unable to calculate SHA-1: %w", err)
	}
	s := hex.EncodeToString(h.Sum(nil))
	prop, err := p.client.SearchBySHA1(s)
	if err != nil {
		return Properties{}, err
	}
	prop.FilePath = filePath
	return prop, nil
}

func isArtifact(name string) bool {
	ext := filepath.Ext(name)
	if ext == ".jar" || ext == ".ear" || ext == ".war" {
		return true
	}
	return false
}

func parseFileName(filePath string) Properties {
	fileName := filepath.Base(filePath)
	packageVersion := jarFileRegEx.FindStringSubmatch(fileName)
	if len(packageVersion) != 3 {
		return Properties{}
	}

	return Properties{
		ArtifactID: packageVersion[1],
		Version:    packageVersion[2],
		FilePath:   filePath,
	}
}

func parsePomProperties(f *zip.File, filePath string) (Properties, error) {
	file, err := f.Open()
	if err != nil {
		return Properties{}, xerrors.Errorf("unable to open pom.properties: %w", err)
	}
	defer file.Close()

	p := Properties{
		FilePath: filePath,
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.GroupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.ArtifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.Version = strings.TrimPrefix(line, "version=")
		}
	}

	if err = scanner.Err(); err != nil {
		return Properties{}, xerrors.Errorf("scan error: %w", err)
	}
	return p, nil
}

type manifest struct {
	implementationVersion  string
	implementationTitle    string
	implementationVendor   string
	implementationVendorId string
	specificationTitle     string
	specificationVersion   string
	specificationVendor    string
	bundleName             string
	bundleVersion          string
	bundleSymbolicName     string
}

func parseManifest(f *zip.File) (manifest, error) {
	file, err := f.Open()
	if err != nil {
		return manifest{}, xerrors.Errorf("unable to open MANIFEST.MF: %w", err)
	}
	defer file.Close()

	var m manifest
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip variables. e.g. Bundle-Name: %bundleName
		ss := strings.Fields(line)
		if len(ss) <= 1 || (len(ss) > 1 && strings.HasPrefix(ss[1], "%")) {
			continue
		}

		// It is not determined which fields are present in each application.
		// In some cases, none of them are included, in which case they cannot be detected.
		switch {
		case strings.HasPrefix(line, "Implementation-Version:"):
			m.implementationVersion = strings.TrimPrefix(line, "Implementation-Version:")
		case strings.HasPrefix(line, "Implementation-Title:"):
			m.implementationTitle = strings.TrimPrefix(line, "Implementation-Title:")
		case strings.HasPrefix(line, "Implementation-Vendor:"):
			m.implementationVendor = strings.TrimPrefix(line, "Implementation-Vendor:")
		case strings.HasPrefix(line, "Implementation-Vendor-Id:"):
			m.implementationVendorId = strings.TrimPrefix(line, "Implementation-Vendor-Id:")
		case strings.HasPrefix(line, "Specification-Version:"):
			m.specificationVersion = strings.TrimPrefix(line, "Specification-Version:")
		case strings.HasPrefix(line, "Specification-Title:"):
			m.specificationTitle = strings.TrimPrefix(line, "Specification-Title:")
		case strings.HasPrefix(line, "Specification-Vendor:"):
			m.specificationVendor = strings.TrimPrefix(line, "Specification-Vendor:")
		case strings.HasPrefix(line, "Bundle-Version:"):
			m.bundleVersion = strings.TrimPrefix(line, "Bundle-Version:")
		case strings.HasPrefix(line, "Bundle-Name:"):
			m.bundleName = strings.TrimPrefix(line, "Bundle-Name:")
		case strings.HasPrefix(line, "Bundle-SymbolicName:"):
			m.bundleSymbolicName = strings.TrimPrefix(line, "Bundle-SymbolicName:")
		}
	}

	if err = scanner.Err(); err != nil {
		return manifest{}, xerrors.Errorf("scan error: %w", err)
	}
	return m, nil
}

func (m manifest) properties(filePath string) Properties {
	groupID, err := m.determineGroupID()
	if err != nil {
		return Properties{}
	}

	artifactID, err := m.determineArtifactID()
	if err != nil {
		return Properties{}
	}

	version, err := m.determineVersion()
	if err != nil {
		return Properties{}
	}

	return Properties{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
		FilePath:   filePath,
	}
}

func (m manifest) determineGroupID() (string, error) {
	var groupID string
	switch {
	case m.implementationVendorId != "":
		groupID = m.implementationVendorId
	case m.bundleSymbolicName != "":
		groupID = m.bundleSymbolicName

		// e.g. "com.fasterxml.jackson.core.jackson-databind" => "com.fasterxml.jackson.core"
		idx := strings.LastIndex(m.bundleSymbolicName, ".")
		if idx > 0 {
			groupID = m.bundleSymbolicName[:idx]
		}
	case m.implementationVendor != "":
		groupID = m.implementationVendor
	case m.specificationVendor != "":
		groupID = m.specificationVendor
	default:
		return "", xerrors.New("no groupID found")
	}
	return strings.TrimSpace(groupID), nil
}

func (m manifest) determineArtifactID() (string, error) {
	var artifactID string
	switch {
	case m.implementationTitle != "":
		artifactID = m.implementationTitle
	case m.specificationTitle != "":
		artifactID = m.specificationTitle
	case m.bundleName != "":
		artifactID = m.bundleName
	default:
		return "", xerrors.New("no artifactID found")
	}
	return strings.TrimSpace(artifactID), nil
}

func (m manifest) determineVersion() (string, error) {
	var version string
	switch {
	case m.implementationVersion != "":
		version = m.implementationVersion
	case m.specificationVersion != "":
		version = m.specificationVersion
	case m.bundleVersion != "":
		version = m.bundleVersion
	default:
		return "", xerrors.New("no version found")
	}
	return strings.TrimSpace(version), nil
}

func removeLibraryDuplicates(libs []types.Library) []types.Library {
	return lo.UniqBy(libs, func(lib types.Library) string {
		return fmt.Sprintf("%s::%s::%s", lib.Name, lib.Version, lib.FilePath)
	})
}
