package jar

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha1" // nolint:gosec
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	mavenversion "github.com/masahiro331/go-mvn-version"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
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
	logger       *log.Logger
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

func NewParser(c Client, opts ...Option) *Parser {
	p := &Parser{
		logger: log.WithPrefix("jar"),
		client: c,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	pkgs, deps, err := p.parseArtifact(p.rootFilePath, p.size, r)
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to parse %s: %w", p.rootFilePath, err)
	}
	return removePackageDuplicates(pkgs), deps, nil
}

func (p *Parser) parseArtifact(filePath string, size int64, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	p.logger.Debug("Parsing Java artifacts...", log.FilePath(filePath))

	// Try to extract artifactId and version from the file name
	// e.g. spring-core-5.3.4-SNAPSHOT.jar => sprint-core, 5.3.4-SNAPSHOT
	fileProps := parseFileName(filePath)

	pkgs, m, foundPomProps, licenses, err := p.traverseZip(size, r, fileProps)
	if err != nil {
		return nil, nil, xerrors.Errorf("zip error: %w", err)
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	// Otherwise, resolve the artifact of the jar itself from MANIFEST.MF / SHA-1 / file name.
	if !foundPomProps {
		props, found, err := p.resolveArtifact(r, m, fileProps)
		if err != nil {
			return nil, nil, err
		}
		if found {
			pkgs = append(pkgs, props.Package())
		}
	}

	// Attach licenses from embedded pom.xml, matched by "groupID:artifactID".
	for i := range pkgs {
		pkg := &pkgs[i]
		// Keep licenses already set by a nested jar from its own pom.xml.
		if len(pkg.Licenses) > 0 {
			continue
		}
		if names, ok := licenses[pkg.Name]; ok {
			pkg.Licenses = names
		}
	}

	return pkgs, nil, nil
}

// resolveArtifact determines the artifact of the jar itself when pom.properties is absent,
// trying MANIFEST.MF, then Maven Central by SHA-1, then a heuristic search by file name.
func (p *Parser) resolveArtifact(r xio.ReadSeekerAt, m manifest, fileProps Properties) (Properties, bool, error) {
	fileName := filepath.Base(fileProps.FilePath)

	manifestProps := m.properties(fileProps.FilePath)
	if p.offline {
		// In offline mode, we will not check if the artifact information is correct.
		if !manifestProps.Valid() {
			p.logger.Debug("Unable to identify POM in offline mode", log.String("file", fileName))
			return Properties{}, false, nil
		}
		return manifestProps, true, nil
	}

	if manifestProps.Valid() {
		// Even if MANIFEST.MF is found, the groupId and artifactId might not be valid.
		// We have to make sure that the artifact exists actually.
		if ok, _ := p.client.Exists(manifestProps.GroupID, manifestProps.ArtifactID); ok {
			// If groupId and artifactId are valid, they will be returned.
			return manifestProps, true, nil
		}
	}

	// If groupId and artifactId are not found, call Maven Central's search API with SHA-1 digest.
	props, err := p.searchBySHA1(r, fileProps.FilePath)
	if err == nil {
		return props, true, nil
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return Properties{}, false, xerrors.Errorf("failed to search by SHA1: %w", err)
	}

	p.logger.Debug("No such POM in the central repositories", log.String("file", fileName))

	// Return when artifactId or version from the file name are empty
	if fileProps.ArtifactID == "" || fileProps.Version == "" {
		return Properties{}, false, nil
	}

	// Try to search groupId by artifactId via sonatype API
	// When some artifacts have the same groupIds, it might result in false detection.
	fileProps.GroupID, err = p.client.SearchByArtifactID(fileProps.ArtifactID, fileProps.Version)
	if err == nil {
		p.logger.Debug("POM was determined in a heuristic way", log.String("file", fileName),
			log.String("artifact", fileProps.String()))
		return fileProps, true, nil
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return Properties{}, false, xerrors.Errorf("failed to search by artifact id: %w", err)
	}

	return Properties{}, false, nil
}

func (p *Parser) traverseZip(size int64, r xio.ReadSeekerAt, fileProps Properties) (
	[]ftypes.Package, manifest, bool, map[string][]string, error) {
	var pkgs []ftypes.Package
	var m manifest
	var foundPomProps bool

	// Licenses declared in embedded META-INF/maven/<g>/<a>/pom.xml, keyed by "groupID:artifactID".
	// The path carries no version, so packages are matched by G:A after the loop
	// (file order in the zip is not guaranteed).
	licenses := make(map[string][]string)

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, manifest{}, false, nil, xerrors.Errorf("zip error: %w", err)
	}

	for _, fileInJar := range zr.File {
		// Collect licenses declared in the embedded META-INF/maven/<g>/<a>/pom.xml.
		if groupID, artifactID, ok := embeddedPomGAV(fileInJar.Name); ok {
			names, err := parsePomLicenses(fileInJar)
			if err != nil {
				p.logger.Debug("Failed to parse licenses", log.String("file", fileInJar.Name), log.Err(err))
				continue
			}
			if len(names) > 0 {
				licenses[packageName(groupID, artifactID)] = names
			}
			continue
		}

		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err := parsePomProperties(fileInJar, fileProps.FilePath)
			if err != nil {
				return nil, manifest{}, false, nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			// Validation of props to avoid getting packages with empty Name/Version
			if props.Valid() {
				pkgs = append(pkgs, props.Package())

				// Check if the pom.properties is for the original JAR/WAR/EAR
				if fileProps.ArtifactID == props.ArtifactID && fileProps.Version == props.Version {
					foundPomProps = true
				}
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			m, err = parseManifest(fileInJar)
			if err != nil {
				return nil, manifest{}, false, nil, xerrors.Errorf("failed to parse MANIFEST.MF: %w", err)
			}
		case isArtifact(fileInJar.Name):
			innerPkgs, _, err := p.parseInnerJar(fileInJar, fileProps.FilePath) // TODO process inner deps
			if err != nil {
				p.logger.Debug("Failed to parse", log.String("file", fileInJar.Name), log.Err(err))
				continue
			}
			pkgs = append(pkgs, innerPkgs...)
		}
	}
	return pkgs, m, foundPomProps, licenses, nil
}

func (p *Parser) parseInnerJar(zf *zip.File, rootPath string) ([]ftypes.Package, []ftypes.Dependency, error) {
	fr, err := zf.Open()
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to open %s: %w", zf.Name, err)
	}

	f, err := xos.CreateTemp("", "jar-inner-")
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
	innerPkgs, innerDeps, err := p.parseArtifact(fullPath, int64(zf.UncompressedSize64), f)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse %s: %w", zf.Name, err)
	}

	return innerPkgs, innerDeps, nil
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
		return Properties{FilePath: filePath}
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

// embeddedPom is a minimal view of an embedded pom.xml: only the license names are needed.
type embeddedPom struct {
	Licenses struct {
		License []struct {
			Name string `xml:"name"`
		} `xml:"license"`
	} `xml:"licenses"`
}

// embeddedPomGAV extracts groupId and artifactId from a path of the form
// META-INF/maven/<groupId>/<artifactId>/pom.xml. The version is not part of the path.
// ok is false when the path is not a Maven descriptor pom.xml.
func embeddedPomGAV(name string) (groupID, artifactID string, ok bool) {
	rel, found := strings.CutPrefix(name, "META-INF/maven/")
	if !found {
		return "", "", false
	}
	rel, found = strings.CutSuffix(rel, "/pom.xml")
	if !found {
		return "", "", false
	}
	groupID, artifactID, found = strings.Cut(rel, "/")
	if !found || groupID == "" || artifactID == "" {
		return "", "", false
	}
	return groupID, artifactID, true
}

// parsePomLicenses returns the raw <license><name> values from an embedded pom.xml.
func parsePomLicenses(f *zip.File) ([]string, error) {
	file, err := f.Open()
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s: %w", f.Name, err)
	}
	defer file.Close()

	return decodePomLicenses(file)
}

// decodePomLicenses decodes a pom.xml and returns the raw <license><name> values.
// Names are kept as-is; normalization happens downstream.
func decodePomLicenses(r io.Reader) ([]string, error) {
	var pom embeddedPom
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&pom); err != nil {
		return nil, xerrors.Errorf("xml decode error: %w", err)
	}

	var names []string
	for _, lic := range pom.Licenses.License {
		if name := strings.TrimSpace(lic.Name); name != "" {
			names = append(names, name)
		}
	}
	return names, nil
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

func removePackageDuplicates(pkgs []ftypes.Package) []ftypes.Package {
	// name::filePath => versions
	var uniq = make(map[string][]mavenversion.Version)
	var uniqPkgs []ftypes.Package
	for _, pkg := range pkgs {
		uniqID := pkg.Name + "::" + pkg.FilePath
		// err is always nil
		// cf. https://github.com/masahiro331/go-mvn-version/blob/d3157d602a08806ad94464c443e0cef1370694a1/version.go#L20-L25
		pkgVer, _ := mavenversion.NewVersion(pkg.Version)
		savedVers, ok := uniq[uniqID]
		if !ok || !slices.ContainsFunc(savedVers, func(v mavenversion.Version) bool {
			// There are times when patch `0` is omitted.
			// So we can't compare versions just as strings
			// for example `2.17.0` and `2.17` must be equal
			return v.Equal(pkgVer)
		}) {
			uniq[uniqID] = append(uniq[uniqID], pkgVer)
			uniqPkgs = append(uniqPkgs, pkg)
		}
	}
	return uniqPkgs
}
