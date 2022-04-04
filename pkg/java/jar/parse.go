package jar

import (
	"archive/zip"
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

const (
	baseURL         = "https://search.maven.org/solrsearch/select"
	idQuery         = `g:"%s" AND a:"%s"`
	artifactIdQuery = `a:"%s" AND p:"jar"`
	sha1Query       = `1:"%s"`
)

var (
	jarFileRegEx = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).jar$`)

	ArtifactNotFoundErr = xerrors.New("no artifact found")
)

type conf struct {
	baseURL      string
	rootFilePath string
	httpClient   *http.Client
	offline      bool
}

type Option func(*conf)

func WithURL(url string) Option {
	return func(c *conf) {
		c.baseURL = url
	}
}

func WithFilePath(filePath string) Option {
	return func(c *conf) {
		c.rootFilePath = filePath
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(c *conf) {
		c.httpClient = client
	}
}

func WithOffline(offline bool) Option {
	return func(c *conf) {
		c.offline = offline
	}

}

func Parse(r dio.ReadSeekerAt, size int64, opts ...Option) ([]types.Library, error) {
	// for HTTP retry
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = logger{}
	retryClient.RetryWaitMin = 20 * time.Second
	retryClient.RetryWaitMax = 5 * time.Minute
	retryClient.RetryMax = 5
	client := retryClient.StandardClient()

	// attempt to read the maven central api url from os environment, if it's
	// not set use the default
	mavenURL, ok := os.LookupEnv("MAVEN_CENTRAL_URL")
	if !ok {
		mavenURL = baseURL
	}

	c := conf{
		baseURL:    mavenURL,
		httpClient: client,
	}
	for _, opt := range opts {
		opt(&c)
	}

	return parseArtifact(c, c.rootFilePath, r, size)
}

func parseArtifact(c conf, fileName string, r dio.ReadSeekerAt, size int64) ([]types.Library, error) {
	log.Logger.Debugw("Parsing Java artifacts...", zap.String("file", fileName))

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, xerrors.Errorf("zip error: %w", err)
	}

	// Try to extract artifactId and version from the file name
	// e.g. spring-core-5.3.4-SNAPSHOT.jar => sprint-core, 5.3.4-SNAPSHOT
	fileName = filepath.Base(fileName)
	fileProps := parseFileName(fileName)

	var libs []types.Library
	var m manifest
	var foundPomProps bool

	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err := parsePomProperties(fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			libs = append(libs, props.library())

			// Check if the pom.properties is for the original JAR/WAR/EAR
			if fileProps.artifactID == props.artifactID && fileProps.version == props.version {
				foundPomProps = true
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			m, err = parseManifest(fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse MANIFEST.MF: %w", err)
			}
		case isArtifact(fileInJar.Name):
			innerLibs, err := parseInnerJar(c, fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			libs = append(libs, innerLibs...)
		}
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	if foundPomProps {
		return libs, nil
	}

	manifestProps := m.properties()
	if c.offline {
		// In offline mode, we will not check if the artifact information is correct.
		if !manifestProps.valid() {
			log.Logger.Debugw("Unable to identify POM in offline mode", zap.String("file", fileName))
			return libs, nil
		}
		return append(libs, manifestProps.library()), nil
	}

	if manifestProps.valid() {
		// Even if MANIFEST.MF is found, the groupId and artifactId might not be valid.
		// We have to make sure that the artifact exists actually.
		if ok, _ := exists(c, manifestProps); ok {
			// If groupId and artifactId are valid, they will be returned.
			return append(libs, manifestProps.library()), nil
		}
	}

	// If groupId and artifactId are not found, call Maven Central's search API with SHA-1 digest.
	p, err := searchBySHA1(c, r)
	if err == nil {
		return append(libs, p.library()), nil
	} else if !xerrors.Is(err, ArtifactNotFoundErr) {
		return nil, xerrors.Errorf("failed to search by SHA1: %w", err)
	}

	log.Logger.Debugw("No such POM in the central repositories", zap.String("file", fileName))

	// Return when artifactId or version from the file name are empty
	if fileProps.artifactID == "" || fileProps.version == "" {
		return libs, nil
	}

	// Try to search groupId by artifactId via sonatype API
	// When some artifacts have the same groupIds, it might result in false detection.
	fileProps.groupID, err = searchByArtifactID(c, fileProps.artifactID)
	if err == nil {
		log.Logger.Debugw("POM was determined in a heuristic way", zap.String("file", fileName),
			zap.String("artifact", fileProps.String()))
		libs = append(libs, fileProps.library())
	} else if !xerrors.Is(err, ArtifactNotFoundErr) {
		return nil, xerrors.Errorf("failed to search by artifact id: %w", err)
	}

	return libs, nil
}

func parseInnerJar(c conf, zf *zip.File) ([]types.Library, error) {
	fr, err := zf.Open()
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s: %w", zf.Name, err)
	}

	f, err := os.CreateTemp("", "inner")
	if err != nil {
		return nil, xerrors.Errorf("unable to create a temp file: %w", err)
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	// Copy the file content to the temp file
	if _, err = io.Copy(f, fr); err != nil {
		return nil, xerrors.Errorf("file copy error: %w", err)
	}

	// Parse jar/war/ear recursively
	innerLibs, err := parseArtifact(c, zf.Name, f, int64(zf.UncompressedSize64))
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", zf.Name, err)
	}

	return innerLibs, nil
}

func isArtifact(name string) bool {
	ext := filepath.Ext(name)
	if ext == ".jar" || ext == ".ear" || ext == ".war" {
		return true
	}
	return false
}

func parseFileName(fileName string) properties {
	packageVersion := jarFileRegEx.FindStringSubmatch(fileName)
	if len(packageVersion) != 3 {
		return properties{}
	}

	return properties{
		artifactID: packageVersion[1],
		version:    packageVersion[2],
	}
}

type properties struct {
	groupID    string
	artifactID string
	version    string
}

func parsePomProperties(f *zip.File) (properties, error) {
	file, err := f.Open()
	if err != nil {
		return properties{}, xerrors.Errorf("unable to open pom.properties: %w", err)
	}
	defer file.Close()

	var p properties
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.groupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.artifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.version = strings.TrimPrefix(line, "version=")
		}
	}

	if err = scanner.Err(); err != nil {
		return properties{}, xerrors.Errorf("scan error: %w", err)
	}
	return p, nil
}

func (p properties) library() types.Library {
	return types.Library{
		Name:    fmt.Sprintf("%s:%s", p.groupID, p.artifactID),
		Version: p.version,
	}
}

func (p properties) valid() bool {
	return p.groupID != "" && p.artifactID != "" && p.version != ""
}

func (p properties) String() string {
	return fmt.Sprintf("%s:%s:%s", p.groupID, p.artifactID, p.version)
}

type manifest struct {
	implementationVersion  string
	implementationTitle    string
	implementationVendorId string
	specificationTitle     string
	specificationVersion   string
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
		case strings.HasPrefix(line, "Implementation-Vendor-Id:"):
			m.implementationVendorId = strings.TrimPrefix(line, "Implementation-Vendor-Id:")
		case strings.HasPrefix(line, "Specification-Version:"):
			m.specificationVersion = strings.TrimPrefix(line, "Specification-Version:")
		case strings.HasPrefix(line, "Specification-Title:"):
			m.specificationTitle = strings.TrimPrefix(line, "Specification-Title:")
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

type apiResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID           string `json:"id"`
			GroupID      string `json:"g"`
			ArtifactID   string `json:"a"`
			Version      string `json:"v"`
			P            string `json:"p"`
			VersionCount int    `json:versionCount`
		} `json:"docs"`
	} `json:"response"`
}

func (m manifest) properties() properties {
	groupID, err := m.determineGroupID()
	if err != nil {
		return properties{}
	}

	artifactID, err := m.determineArtifactID()
	if err != nil {
		return properties{}
	}

	version, err := m.determineVersion()
	if err != nil {
		return properties{}
	}

	return properties{
		groupID:    groupID,
		artifactID: artifactID,
		version:    version,
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

func exists(c conf, p properties) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL, nil)
	if err != nil {
		return false, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(idQuery, p.groupID, p.artifactID))
	q.Set("rows", "1")
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, xerrors.Errorf("json decode error: %w", err)
	}
	return res.Response.NumFound > 0, nil
}

func searchBySHA1(c conf, r io.ReadSeeker) (properties, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return properties{}, xerrors.Errorf("file seek error: %w", err)
	}

	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return properties{}, xerrors.Errorf("unable to calculate SHA-1: %w", err)
	}
	digest := hex.EncodeToString(h.Sum(nil))

	req, err := http.NewRequest(http.MethodGet, c.baseURL, nil)
	if err != nil {
		return properties{}, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(sha1Query, digest))
	q.Set("rows", "1")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return properties{}, xerrors.Errorf("sha1 search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return properties{}, xerrors.Errorf("status %s from %s", resp.Status, req.URL.String())
	}

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return properties{}, xerrors.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return properties{}, xerrors.Errorf("digest %s: %w", digest, ArtifactNotFoundErr)
	}

	// Some artifacts might have the same SHA-1 digests.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].ID < docs[j].ID
	})
	d := docs[0]

	return properties{
		groupID:    d.GroupID,
		artifactID: d.ArtifactID,
		version:    d.Version,
	}, nil
}

func searchByArtifactID(c conf, artifactID string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL, nil)
	if err != nil {
		return "", xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(artifactIdQuery, artifactID))
	q.Set("rows", "20")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", xerrors.Errorf("artifactID search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", xerrors.Errorf("status %s from %s", resp.Status, req.URL.String())
	}

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", xerrors.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, ArtifactNotFoundErr)
	}

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].VersionCount > docs[j].VersionCount
	})
	d := docs[0]

	return d.GroupID, nil
}
