package jar

import (
	"archive/zip"
	"bufio"
	"context"
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

	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
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
	logger                 *log.Logger
	rootFilePath           string
	offline                bool
	checksum               bool
	size                   int64
	licenseConfidenceLevel float64

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

// WithChecksum enables calculation of the SHA-1 digest for every archive
// (not only the ones that are looked up by SHA-1) and saving it to Package.Digest.
func WithChecksum(checksum bool) Option {
	return func(p *Parser) {
		p.checksum = checksum
	}
}

func WithSize(size int64) Option {
	return func(p *Parser) {
		p.size = size
	}
}

func WithLicenseClassifierConfidenceLevel(level float64) Option {
	return func(p *Parser) {
		p.licenseConfidenceLevel = level
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
	pkgs, deps, err := p.parsePackages(filePath, size, r)
	if err != nil {
		return nil, nil, err
	}

	// When a checksum is requested, every package must carry the digest of its
	// own file. Packages from nested archives (and the one resolved by
	// searchBySHA1) already have it, so fill in this archive's digest only for
	// the packages that are still missing one.
	if p.checksum {
		if err := fillArchiveDigest(pkgs, r); err != nil {
			return nil, nil, xerrors.Errorf("unable to set digest for %s: %w", filePath, err)
		}
	}

	return pkgs, deps, nil
}

func (p *Parser) parsePackages(filePath string, size int64, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	p.logger.Debug("Parsing Java artifacts...", log.FilePath(filePath))

	// Try to extract artifactId and version from the file name
	// e.g. spring-core-5.3.4-SNAPSHOT.jar => sprint-core, 5.3.4-SNAPSHOT
	fileProps := parseFileName(filePath)

	pkgs, m, foundPomProps, licenseFile, err := p.traverseZip(size, r, fileProps)
	if err != nil {
		return nil, nil, xerrors.Errorf("zip error: %w", err)
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	// Otherwise, resolve the artifact of the jar itself from MANIFEST.MF / SHA-1 / file name.
	// Such an artifact has no embedded pom.xml (maven-archiver writes pom.xml and
	// pom.properties together), so it carries no pom.xml license.
	if !foundPomProps {
		pkg, found, err := p.resolveArtifact(r, m, fileProps)
		if err != nil {
			return nil, nil, err
		}
		if found {
			pkgs = append(pkgs, pkg)
		}
	}

	// Classify and attach the LICENSE file now that the jar's own artifact is resolved
	// (it may have been added above from MANIFEST.MF / SHA-1 / file name).
	attachManifestLicenses(pkgs, fileProps.FilePath, m.licenses)
	p.attachFileLicenses(pkgs, fileProps.FilePath, licenseFile)

	return pkgs, nil, nil
}

// resolveArtifact determines the artifact of the jar itself when pom.properties is absent,
// trying MANIFEST.MF, then Maven Central by SHA-1, then a heuristic search by file name.
func (p *Parser) resolveArtifact(r xio.ReadSeekerAt, m manifest, fileProps Properties) (ftypes.Package, bool, error) {
	fileName := filepath.Base(fileProps.FilePath)

	manifestProps := m.properties(fileProps.FilePath)
	if p.offline {
		// In offline mode, we will not check if the artifact information is correct.
		if !manifestProps.Valid() {
			p.logger.Debug("Unable to identify POM in offline mode", log.String("file", fileName))
			return ftypes.Package{}, false, nil
		}
		return manifestProps.Package(), true, nil
	}

	if manifestProps.Valid() {
		// Even if MANIFEST.MF is found, the groupId and artifactId might not be valid.
		// We have to make sure that the artifact exists actually.
		if ok, _ := p.client.Exists(manifestProps.GroupID, manifestProps.ArtifactID); ok {
			// If groupId and artifactId are valid, they will be returned.
			return manifestProps.Package(), true, nil
		}
	}

	// If groupId and artifactId are not found, call Maven Central's search API with SHA-1 digest.
	pkg, err := p.searchBySHA1(r, fileProps.FilePath)
	if err == nil {
		return pkg, true, nil
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return ftypes.Package{}, false, xerrors.Errorf("failed to search by SHA1: %w", err)
	}

	p.logger.Debug("No such POM in the central repositories", log.String("file", fileName))

	// Return when artifactId or version from the file name are empty
	if fileProps.ArtifactID == "" || fileProps.Version == "" {
		return ftypes.Package{}, false, nil
	}

	// Try to search groupId by artifactId via sonatype API
	// When some artifacts have the same groupIds, it might result in false detection.
	fileProps.GroupID, err = p.client.SearchByArtifactID(fileProps.ArtifactID, fileProps.Version)
	if err == nil {
		p.logger.Debug("POM was determined in a heuristic way", log.String("file", fileName),
			log.String("artifact", fileProps.String()))
		return fileProps.Package(), true, nil
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return ftypes.Package{}, false, xerrors.Errorf("failed to search by artifact id: %w", err)
	}

	return ftypes.Package{}, false, nil
}

// fillArchiveDigest sets the SHA-1 digest of the archive (r) on every package
// that does not have a digest yet. The digest is calculated lazily, so the
// archive is not read when all packages already carry their own digest.
//
// Packages that have no file of their own — e.g. dependencies flattened into a
// shaded/uber JAR, which only leave a bundled pom.properties behind — all share
// this archive's digest. That is consistent with their FilePath, which is also
// the enclosing archive, so the digest stays aligned with the file it refers to.
func fillArchiveDigest(pkgs []ftypes.Package, r xio.ReadSeekerAt) error {
	var d digest.Digest
	for i := range pkgs {
		if pkgs[i].Digest != "" {
			continue
		}
		// Compute the archive digest at most once and reuse it afterwards.
		// An empty d means it has not been calculated yet.
		if d == "" {
			if _, err := r.Seek(0, io.SeekStart); err != nil {
				return xerrors.Errorf("file seek error: %w", err)
			}
			var err error
			if d, err = digest.CalcSHA1(r); err != nil {
				return xerrors.Errorf("unable to calculate SHA-1: %w", err)
			}
		}
		pkgs[i].Digest = d
	}
	return nil
}

func (p *Parser) traverseZip(size int64, r xio.ReadSeekerAt, fileProps Properties) (
	[]ftypes.Package, manifest, bool, *zip.File, error) {
	var pkgs []ftypes.Package
	var m manifest
	var foundPomProps bool
	var licenseFiles []*zip.File

	// Licenses declared in embedded META-INF/maven/<g>/<a>/pom.xml, keyed by "groupID:artifactID".
	// The path carries no version, so packages are matched by G:A after the loop
	// (file order in the zip is not guaranteed).
	pomLicenses := make(map[string][]string)

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, manifest{}, false, nil, xerrors.Errorf("zip error: %w", err)
	}

	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.xml":
			// Collect licenses declared in the embedded META-INF/maven/<g>/<a>/pom.xml.
			groupID, artifactID, ok := embeddedPomGAV(fileInJar.Name)
			if !ok {
				break
			}
			names, err := parsePomLicenses(fileInJar)
			if err != nil {
				p.logger.Debug("Failed to parse licenses", log.String("file", fileInJar.Name), log.Err(err))
				break
			}
			if len(names) > 0 {
				pomLicenses[packageName(groupID, artifactID)] = names
			}
		case isJarLicenseFile(fileInJar.Name):
			licenseFiles = append(licenseFiles, fileInJar)
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

	// Attach licenses from embedded pom.xml, matched by "groupID:artifactID".
	attachPomLicenses(pkgs, pomLicenses)

	var licenseFile *zip.File
	if len(licenseFiles) == 1 {
		licenseFile = licenseFiles[0]
	}

	return pkgs, m, foundPomProps, licenseFile, nil
}

// attachPomLicenses attaches licenses declared in embedded pom.xml files to packages,
// matched by "groupID:artifactID". Packages that already have a license (e.g. set by a
// nested jar from its own pom.xml) are left untouched.
func attachPomLicenses(pkgs []ftypes.Package, pomLicenses map[string][]string) {
	for i := range pkgs {
		pkg := &pkgs[i]
		if len(pkg.Licenses) > 0 {
			continue
		}
		if names, ok := pomLicenses[pkg.Name]; ok {
			pkg.Licenses = names
		}
	}
}

// attachManifestLicenses attaches Jenkins plugin licenses declared in MANIFEST.MF
// to the jar's own package when a single unambiguous package belongs to this jar.
func attachManifestLicenses(pkgs []ftypes.Package, filePath string, licenses []string) {
	if len(licenses) == 0 {
		return
	}

	var pkg *ftypes.Package

	for i := range pkgs {
		if pkgs[i].FilePath != filePath {
			continue
		}
		if pkg != nil {
			return // more than one package belongs to this jar
		}
		pkg = &pkgs[i]
	}

	if pkg == nil || len(pkg.Licenses) > 0 {
		return
	}

	pkg.Licenses = licenses
}

// attachFileLicenses classifies the LICENSE file packed in a jar and attaches it to the
// jar's own package, but only when the owner is unambiguous: a single LICENSE file, a
// single package belonging to this jar, and no license from its pom.xml yet.
func (p *Parser) attachFileLicenses(pkgs []ftypes.Package, filePath string, licenseFile *zip.File) {
	if licenseFile == nil {
		return
	}

	var pkg *ftypes.Package

	for i := range pkgs {
		if pkgs[i].FilePath != filePath {
			continue
		}
		if pkg != nil {
			return // more than one package belongs to this jar
		}
		pkg = &pkgs[i]
	}

	if pkg == nil {
		return // no package belongs to this jar
	}

	if len(pkg.Licenses) > 0 {
		return
	}

	names, err := p.classifyPackedLicense(licenseFile)
	if err != nil {
		p.logger.Debug("Failed to classify license file", log.FilePath(licenseFile.Name), log.Err(err))
		return
	}
	if len(names) > 0 {
		pkg.Licenses = names
	}
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

func (p *Parser) searchBySHA1(r io.ReadSeeker, filePath string) (ftypes.Package, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return ftypes.Package{}, xerrors.Errorf("file seek error: %w", err)
	}
	d, err := digest.CalcSHA1(r)
	if err != nil {
		return ftypes.Package{}, xerrors.Errorf("unable to calculate SHA-1: %w", err)
	}

	prop, err := p.client.SearchBySHA1(d.Encoded())
	if err != nil {
		return ftypes.Package{}, err
	}
	prop.FilePath = filePath

	pkg := prop.Package()
	// searchBySHA1 has already calculated the archive's SHA-1, so stamp it on the
	// resolved package to avoid recalculating it in fillArchiveDigest.
	if p.checksum {
		pkg.Digest = d
	}
	return pkg, nil
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

// isJarLicenseFile reports whether a zip entry is a license file eligible for
// classification: located at the jar root or directly under META-INF/ (not in a subdirectory),
// with a base name whose stem is license/licence/copyright (e.g. LICENSE, LICENSE.txt).
// Vendored licenses use prefixed names (e.g. FastDoubleParser-LICENSE) or nested
// paths, so they are intentionally excluded.
func isJarLicenseFile(name string) bool {
	dir := path.Dir(name)
	if dir != "." && dir != "META-INF" {
		return false
	}
	base := path.Base(name)
	if isArtifact(base) {
		return false // e.g. license.jar is a nested archive, not a license file
	}
	stem := strings.TrimSuffix(base, path.Ext(base))
	return licensing.LicenseFileNames.Contains(stem)
}

// classifyPackedLicense classifies a LICENSE file packed in a jar and returns the
// detected license names.
func (p *Parser) classifyPackedLicense(f *zip.File) ([]string, error) {
	file, err := f.Open()
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s: %w", f.Name, err)
	}
	defer file.Close()

	lf, err := licensing.Classify(f.Name, file, p.licenseConfidenceLevel)
	if err != nil {
		return nil, xerrors.Errorf("license classification error: %w", err)
	}
	if lf == nil {
		return nil, nil
	}
	return lf.Findings.Names(), nil
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
	licenses               []string
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
		default:
			key, value, ok := strings.Cut(line, ":")
			if !ok || !isPluginLicenseNameKey(key) {
				continue
			}
			if name := strings.TrimSpace(value); name != "" {
				m.licenses = append(m.licenses, name)
			}
		}
	}

	if err = scanner.Err(); err != nil {
		return manifest{}, xerrors.Errorf("scan error: %w", err)
	}
	return m, nil
}

func isPluginLicenseNameKey(key string) bool {
	if key == "Plugin-License-Name" {
		return true
	}
	suffix, ok := strings.CutPrefix(key, "Plugin-License-Name-")
	if !ok || suffix == "" {
		return false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
