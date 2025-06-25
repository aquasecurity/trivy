package pom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"
)

// Default Maven central URL
const defaultCentralUrl = "https://repo.maven.apache.org/maven2/"

var mavenHttpCacheTtl = func() time.Duration {
	if ttlStr := os.Getenv("MAVEN_CACHE_TTL_HOURS"); ttlStr != "" {
		if ttl, err := strconv.Atoi(ttlStr); err == nil && ttl > 0 {
			return time.Duration(ttl) * time.Hour
		}
	}

	// Default TTL
	return 6 * time.Hour
}()

// Maximum number of I/O timeouts Trivy will tolerate before skipping future requests to the domain
// Without this, some scans can take a very long time because every request to a domain times out, one by one
const MaxDomainTimeouts = 3

// Cache settings

const (
	mavenHttpCacheDir = "maven_http_cache"
	domainsFileName   = "domains.json"
)

// Ordered list of URLs to use to fetch Maven dependency metadata.
// If there is an error fetching a dependency from a URL, the next URL is used, and so on.
var mavenReleaseRepos []string

// mavenHttpCacheEntry represents a cached HTTP response
type mavenHttpCacheEntry struct {
	Data       []byte              `json:"data"`
	ExpiresAt  time.Time           `json:"expires_at"`
	Headers    map[string][]string `json:"headers"`
	StatusCode int                 `json:"status_code"`
	// The URL this cached entry was resolved from, for record-keeping
	Url string `json:"url"`
}

// mavenHttpCache handles filesystem caching of HTTP responses
type mavenHttpCache struct {
	cacheDir string
	// cache entry TTL
	ttl             time.Duration
	domainsFilePath string
	domainBlocklist []blocklistEntry
	domainTimeouts  map[string]int
	logger          *log.Logger
	initialized     bool
}

func (c *mavenHttpCache) logDomainBlocklist() {
	names := make([]string, len(c.domainBlocklist))
	for i, entry := range c.domainBlocklist {
		names[i] = entry.Name
	}

	c.logger.Debug(
		"Maven cache domainBlocklist ",
		log.String("domainBlocklist", strings.Join(names, ", ")),
	)
}

func newMavenHttpCache(logger *log.Logger) *mavenHttpCache {
	var cacheDir string = filepath.Join(cache.DefaultDir(), mavenHttpCacheDir)
	var domainsFilePath string = filepath.Join(cacheDir, domainsFileName)
	var ttl time.Duration = mavenHttpCacheTtl

	logger.Debug(
		"New Maven cache ",
		log.String("cacheDir", cacheDir),
		log.Duration("ttl", ttl),
		log.String("domainsFilePath", domainsFilePath),
	)

	var cache = &mavenHttpCache{
		cacheDir:        cacheDir,
		ttl:             ttl,
		domainsFilePath: domainsFilePath,
		domainBlocklist: []blocklistEntry{},
		domainTimeouts:  make(map[string]int),
		logger:          logger,
		initialized:     false,
	}

	cache.domainBlocklist, _ = cache.readDomainBlocklist()
	cache.logDomainBlocklist()

	// Ensure cache directory exists
	if err := os.MkdirAll(cache.cacheDir, 0755); err != nil {
		logger.Warn(
			"Error creating Maven cache directory ",
			log.Err(err),
		)
		return cache
	}

	cache.initialized = true

	return cache
}

// cacheKey generates a cache key for the given URL
func (c *mavenHttpCache) cacheKey(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:])
}

// get retrieves a cached HTTP response if it exists and hasn't expired
func (c *mavenHttpCache) get(path string) (*mavenHttpCacheEntry, error) {
	if !c.initialized {
		return nil, xerrors.Errorf("Maven cache is not initialized")
	}

	key := c.cacheKey(path)
	cacheFile := filepath.Join(c.cacheDir, key+".json")

	// Check if cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil, nil // Cache miss
	}

	// Read cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, xerrors.Errorf("failed to read cache file: %w", err)
	}

	var entry mavenHttpCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// If we can't parse the cache file, remove it and return cache miss
		_ = os.Remove(cacheFile)
		return nil, nil
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		// Lazy purge expired entry
		_ = os.Remove(cacheFile)
		return nil, nil
	}

	return &entry, nil
}

// set stores an HTTP response in the cache
func (c *mavenHttpCache) set(url string, path string, data []byte, headers map[string][]string, statusCode int) error {
	if !c.initialized {
		return xerrors.Errorf("Maven cache is not initialized")
	}

	key := c.cacheKey(path)
	cacheFile := filepath.Join(c.cacheDir, key+".json")

	entry := mavenHttpCacheEntry{
		Data:       data,
		ExpiresAt:  time.Now().Add(c.ttl),
		Headers:    headers,
		StatusCode: statusCode,
		Url:        url,
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return xerrors.Errorf("failed to marshal cache entry: %w", err)
	}

	if err := os.WriteFile(cacheFile, jsonData, 0644); err != nil {
		return xerrors.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

type blocklistEntry struct {
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
}

type domainsJson struct {
	Blocklist []blocklistEntry `json:"blocklist"`
}

func isMavenReleaseDomain(name string) bool {
	for _, repoUrl := range mavenReleaseRepos {
		u, err := url.Parse(repoUrl)

		if err != nil {
			continue // skip malformed URLs
		}

		if name == u.Host {
			return true
		}
	}

	return false
}

// Blocklist a domain for the cache TTL period. Repos in mavenReleaseRepos cannot be blocklisted
func (c *mavenHttpCache) blocklistDomain(name string) error {
	c.logger.Debug("blocklistDomain[" + name + "] blocklisting domain...")
	var newBlocklistEntry blocklistEntry = blocklistEntry{
		Name:      name,
		ExpiresAt: time.Now().Add(c.ttl),
	}

	if !c.initialized {
		c.logger.Debug("blocklistDomain[" + name + "] Maven cache is not initialized. Exiting")
		return xerrors.Errorf("Maven cache is not initialized")
	}

	currentDomainBlocklist, err := c.readDomainBlocklist()

	c.logger.Debug("blocklistDomain[" + name + "] Read domain blocklist")

	if err != nil {
		c.logger.Debug("blocklistDomain["+name+"] Failed to read domain blocklist", log.Err(err))
		return xerrors.Errorf("Failed to read domain blocklist, skipping blocklist: %w", err)
	}

	// Skip blocklisting configured Maven release domains to avoid DoS
	if isMavenReleaseDomain(name) {
		c.logger.Debug("blocklistDomain[" + name + "] Domain is Maven release domain, skipping blocklist")
		return nil
	}

	// Skip adding the domain to the blocklist if it's already present
	for _, d := range currentDomainBlocklist {
		if d.Name == name {
			c.logger.Debug("blocklistDomain[" + name + "] Domain is already in blocklist, skipping blocklist")
			return nil
		}
	}

	// Add the new domain to blocklist
	currentDomainBlocklist = append(currentDomainBlocklist, newBlocklistEntry)
	// Update the in-memory blocklist
	c.domainBlocklist = currentDomainBlocklist

	// Encode and write back
	jsonData, err := json.Marshal(domainsJson{
		Blocklist: currentDomainBlocklist,
	})

	if err != nil {
		c.logger.Debug("blocklistDomain["+name+"] failed to marshal domains json", log.Err(err))
		return xerrors.Errorf("failed to marshal domains json: %w", err)
	}

	if err := os.WriteFile(c.domainsFilePath, jsonData, 0644); err != nil {
		c.logger.Debug("blocklistDomain["+name+"] failed to write domains json file", log.Err(err))
		return xerrors.Errorf("failed to write domains json file: %w", err)
	}

	// Success
	return nil
}

// readDomainBlocklist reads and returns the current domain blocklist, filtering out expired entries
func (c *mavenHttpCache) readDomainBlocklist() ([]blocklistEntry, error) {
	if _, err := os.Stat(c.domainsFilePath); os.IsNotExist(err) {
		c.logger.Debug("Domains file does not exist, default to empty blocklist")
		return []blocklistEntry{}, nil
	}

	var currentDomainBlocklist []blocklistEntry

	b, err := os.ReadFile(c.domainsFilePath)
	if err != nil {
		return []blocklistEntry{}, xerrors.Errorf("Failed to read domains file: %w", err)
	}

	if err := json.Unmarshal(b, &currentDomainBlocklist); err != nil {
		return []blocklistEntry{}, xerrors.Errorf("Failed to unmarshal domains file: %w", err)
	}

	now := time.Now()

	var unexpiredBlocklist []blocklistEntry
	for _, d := range currentDomainBlocklist {
		if now.Before(d.ExpiresAt) {
			unexpiredBlocklist = append(unexpiredBlocklist, d)
		}
	}

	return unexpiredBlocklist, nil
}

// Determine whether a domain is blocklisted by consulting the in-memory blocklist (synced with filesystem blocklist at process startup)
func (c *mavenHttpCache) isDomainBlocklisted(name string) bool {
	if !c.initialized {
		return false
	}

	now := time.Now()

	for _, d := range c.domainBlocklist {
		if now.Before(d.ExpiresAt) {
			if d.Name == name {
				return true
			}
		}
	}

	return false
}

func init() {
	if url, ok := os.LookupEnv("MAVEN_CENTRAL_URL"); ok {
		// Use the default Maven central URL in case the
		mavenReleaseRepos = []string{url, defaultCentralUrl}
	} else {
		mavenReleaseRepos = []string{defaultCentralUrl}
	}
}

type options struct {
	offline             bool
	releaseRemoteRepos  []string
	snapshotRemoteRepos []string
}

type option func(*options)

func WithOffline(offline bool) option {
	return func(opts *options) {
		opts.offline = offline
	}
}

func WithReleaseRemoteRepos(repos []string) option {
	return func(opts *options) {
		opts.releaseRemoteRepos = repos
	}
}

func WithSnapshotRemoteRepos(repos []string) option {
	return func(opts *options) {
		opts.snapshotRemoteRepos = repos
	}
}

type Parser struct {
	logger              *log.Logger
	rootPath            string
	cache               pomCache
	mavenHttpCache      *mavenHttpCache
	localRepository     string
	releaseRemoteRepos  []string
	snapshotRemoteRepos []string
	offline             bool
	servers             []Server
}

func NewParser(filePath string, opts ...option) *Parser {
	var logger = log.WithPrefix("pom")

	o := &options{
		offline:            false,
		releaseRemoteRepos: mavenReleaseRepos, // Maven doesn't use central repository for snapshot dependencies
	}

	logger.Debug("Creating parser", log.String("releaseRemoteRepos", strings.Join(mavenReleaseRepos, ", ")))

	for _, opt := range opts {
		opt(o)
	}

	s := readSettings()
	localRepository := s.LocalRepository
	if localRepository == "" {
		homeDir, _ := os.UserHomeDir()
		localRepository = filepath.Join(homeDir, ".m2", "repository")
	}

	return &Parser{
		logger:              logger,
		rootPath:            filepath.Clean(filePath),
		cache:               newPOMCache(),
		mavenHttpCache:      newMavenHttpCache(logger),
		localRepository:     localRepository,
		releaseRemoteRepos:  o.releaseRemoteRepos,
		snapshotRemoteRepos: o.snapshotRemoteRepos,
		offline:             o.offline,
		servers:             s.Servers,
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	content, err := parsePom(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse POM: %w", err)
	}

	root := &pom{
		filePath: p.rootPath,
		content:  content,
	}

	// Analyze root POM
	result, err := p.analyze(root, analysisOptions{lineNumber: true})
	if err != nil {
		return nil, nil, xerrors.Errorf("analyze error (%s): %w", p.rootPath, err)
	}

	// Cache root POM
	p.cache.put(result.artifact, result)

	return p.parseRoot(root.artifact(), make(map[string]struct{}))
}

func (p *Parser) parseRoot(root artifact, uniqModules map[string]struct{}) ([]ftypes.Package, []ftypes.Dependency, error) {
	// Prepare a queue for dependencies
	queue := newArtifactQueue()

	// Enqueue root POM
	root.Relationship = ftypes.RelationshipRoot
	root.Module = false
	queue.enqueue(root)

	var (
		pkgs              ftypes.Packages
		deps              ftypes.Dependencies
		rootDepManagement []pomDependency
		uniqArtifacts     = make(map[string]artifact)
		uniqDeps          = make(map[string][]string)
	)

	// Iterate direct and transitive dependencies
	for !queue.IsEmpty() {
		art := queue.dequeue()

		// Modules should be handled separately so that they can have independent dependencies.
		// It means multi-module allows for duplicate dependencies.
		if art.Module {
			if _, ok := uniqModules[art.String()]; ok {
				continue
			}
			uniqModules[art.String()] = struct{}{}

			modulePkgs, moduleDeps, err := p.parseRoot(art, uniqModules)
			if err != nil {
				return nil, nil, err
			}

			pkgs = append(pkgs, modulePkgs...)
			if moduleDeps != nil {
				deps = append(deps, moduleDeps...)
			}
			continue
		}

		// For soft requirements, skip dependency resolution that has already been resolved.
		if uniqueArt, ok := uniqArtifacts[art.Name()]; ok {
			if !uniqueArt.Version.shouldOverride(art.Version) {
				continue
			}
			// mark artifact as Direct, if saved artifact is Direct
			// take a look `hard requirement for the specified version` test
			if uniqueArt.Relationship == ftypes.RelationshipRoot || uniqueArt.Relationship == ftypes.RelationshipDirect {
				art.Relationship = uniqueArt.Relationship
			}
			// We don't need to overwrite dependency location for hard links
			if uniqueArt.Locations != nil {
				art.Locations = uniqueArt.Locations
			}
		}

		result, err := p.resolve(art, rootDepManagement)
		if err != nil {
			return nil, nil, xerrors.Errorf("resolve error (%s): %w", art, err)
		}

		if art.Relationship == ftypes.RelationshipRoot {
			// Managed dependencies in the root POM affect transitive dependencies
			rootDepManagement = p.resolveDepManagement(result.properties, result.dependencyManagement)

			// mark its dependencies as "direct"
			result.dependencies = lo.Map(result.dependencies, func(dep artifact, _ int) artifact {
				dep.Relationship = ftypes.RelationshipDirect
				return dep
			})
		}

		// Parse, cache, and enqueue modules.
		for _, relativePath := range result.modules {
			moduleArtifact, err := p.parseModule(result.filePath, relativePath)
			if err != nil {
				p.logger.Debug("Unable to parse the module",
					log.FilePath(result.filePath), log.Err(err))
				continue
			}

			queue.enqueue(moduleArtifact)
		}

		// Resolve transitive dependencies later
		queue.enqueue(result.dependencies...)

		// Offline mode may be missing some fields.
		if !art.IsEmpty() {
			// Override the version
			uniqArtifacts[art.Name()] = artifact{
				Version:      art.Version,
				Licenses:     result.artifact.Licenses,
				Relationship: art.Relationship,
				Locations:    art.Locations,
			}

			// save only dependency names
			// version will be determined later
			dependsOn := lo.Map(result.dependencies, func(a artifact, _ int) string {
				return a.Name()
			})
			uniqDeps[packageID(art.Name(), art.Version.String())] = dependsOn
		}
	}

	// Convert to []ftypes.Package and []ftypes.Dependency
	for name, art := range uniqArtifacts {
		pkg := ftypes.Package{
			ID:           packageID(name, art.Version.String()),
			Name:         name,
			Version:      art.Version.String(),
			Licenses:     art.Licenses,
			Relationship: art.Relationship,
			Locations:    art.Locations,
		}
		pkgs = append(pkgs, pkg)

		// Convert dependency names into dependency IDs
		dependsOn := lo.FilterMap(uniqDeps[pkg.ID], func(dependOnName string, _ int) (string, bool) {
			ver := depVersion(dependOnName, uniqArtifacts)
			return packageID(dependOnName, ver), ver != ""
		})

		sort.Strings(dependsOn)
		if len(dependsOn) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkg.ID,
				DependsOn: dependsOn,
			})
		}
	}

	sort.Sort(pkgs)
	sort.Sort(deps)

	return pkgs, deps, nil
}

// depVersion finds dependency in uniqArtifacts and return its version
func depVersion(depName string, uniqArtifacts map[string]artifact) string {
	if art, ok := uniqArtifacts[depName]; ok {
		return art.Version.String()
	}
	return ""
}

func (p *Parser) parseModule(currentPath, relativePath string) (artifact, error) {
	// modulePath: "root/" + "module/" => "root/module"
	module, err := p.openRelativePom(currentPath, relativePath)
	if err != nil {
		return artifact{}, xerrors.Errorf("unable to open the relative path: %w", err)
	}

	result, err := p.analyze(module, analysisOptions{})
	if err != nil {
		return artifact{}, xerrors.Errorf("analyze error: %w", err)
	}

	moduleArtifact := module.artifact()
	moduleArtifact.Module = true // TODO: introduce RelationshipModule?

	p.cache.put(moduleArtifact, result)

	return moduleArtifact, nil
}

func (p *Parser) resolve(art artifact, rootDepManagement []pomDependency) (analysisResult, error) {
	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(art); result != nil {
		return *result, nil
	}

	// We can't resolve a dependency without a version.
	// So let's just keep this dependency.
	if art.Version.String() == "" {
		return analysisResult{
			artifact: art,
		}, nil
	}

	p.logger.Debug("Resolving...", log.String("group_id", art.GroupID),
		log.String("artifact_id", art.ArtifactID), log.String("version", art.Version.String()))
	pomContent, err := p.tryRepository(art.GroupID, art.ArtifactID, art.Version.String())
	if err != nil {
		p.logger.Debug("Repository error", log.Err(err))
	}
	result, err := p.analyze(pomContent, analysisOptions{
		exclusions:    art.Exclusions,
		depManagement: rootDepManagement,
	})
	if err != nil {
		return analysisResult{}, xerrors.Errorf("analyze error: %w", err)
	}

	p.cache.put(art, result)
	return result, nil
}

type analysisResult struct {
	filePath             string
	artifact             artifact
	dependencies         []artifact
	dependencyManagement []pomDependency // Keep the order of dependencies in 'dependencyManagement'
	properties           map[string]string
	modules              []string
}

type analysisOptions struct {
	exclusions    map[string]struct{}
	depManagement []pomDependency // from the root POM
	lineNumber    bool            // Save line numbers
}

func (p *Parser) analyze(pom *pom, opts analysisOptions) (analysisResult, error) {
	if pom == nil || pom.content == nil {
		return analysisResult{}, nil
	}

	// Update remoteRepositories
	pomReleaseRemoteRepos, pomSnapshotRemoteRepos := pom.repositories(p.servers)
	p.releaseRemoteRepos = lo.Uniq(append(pomReleaseRemoteRepos, p.releaseRemoteRepos...))
	p.snapshotRemoteRepos = lo.Uniq(append(pomSnapshotRemoteRepos, p.snapshotRemoteRepos...))

	// We need to forward dependencyManagements from current and root pom to Parent,
	// to use them for dependencies in parent.
	// For better understanding see the following tests:
	// - `dependency from parent uses version from child pom depManagement`
	// - `dependency from parent uses version from root pom depManagement`
	//
	// depManagements from root pom has higher priority than depManagements from current pom.
	depManagementForParent := lo.UniqBy(append(opts.depManagement, pom.content.DependencyManagement.Dependencies.Dependency...),
		func(dep pomDependency) string {
			return dep.Name()
		})

	// Parent
	parent, err := p.parseParent(pom.filePath, pom.content.Parent, depManagementForParent)
	if err != nil {
		return analysisResult{}, xerrors.Errorf("parent error: %w", err)
	}

	// Inherit values/properties from parent
	pom.inherit(parent)

	// Generate properties
	props := pom.properties()

	// dependencyManagements have the next priority:
	// 1. Managed dependencies from this POM
	// 2. Managed dependencies from parent of this POM
	depManagement := p.mergeDependencyManagements(pom.content.DependencyManagement.Dependencies.Dependency,
		parent.dependencyManagement)

	// Merge dependencies. Child dependencies must be preferred than parent dependencies.
	// Parents don't have to resolve dependencies.
	deps := p.parseDependencies(pom.content.Dependencies.Dependency, props, depManagement, opts)
	deps = p.mergeDependencies(parent.dependencies, deps, opts.exclusions)

	return analysisResult{
		filePath:             pom.filePath,
		artifact:             pom.artifact(),
		dependencies:         deps,
		dependencyManagement: depManagement,
		properties:           props,
		modules:              pom.content.Modules.Module,
	}, nil
}

func (p *Parser) mergeDependencyManagements(depManagements ...[]pomDependency) []pomDependency {
	uniq := make(map[string]struct{})
	var depManagement []pomDependency
	// The preceding argument takes precedence.
	for _, dm := range depManagements {
		for _, dep := range dm {
			if _, ok := uniq[dep.Name()]; ok {
				continue
			}
			depManagement = append(depManagement, dep)
			uniq[dep.Name()] = struct{}{}
		}
	}
	return depManagement
}

func (p *Parser) parseDependencies(deps []pomDependency, props map[string]string, depManagement []pomDependency,
	opts analysisOptions) []artifact {
	// Imported POMs often have no dependencies, so dependencyManagement resolution can be skipped.
	if len(deps) == 0 {
		return nil
	}

	// Resolve dependencyManagement
	depManagement = p.resolveDepManagement(props, depManagement)

	rootDepManagement := opts.depManagement
	var dependencies []artifact
	for _, d := range deps {
		// Resolve dependencies
		d = d.Resolve(props, depManagement, rootDepManagement)

		if (d.Scope != "" && d.Scope != "compile" && d.Scope != "runtime") || d.Optional {
			continue
		}

		dependencies = append(dependencies, d.ToArtifact(opts))
	}
	return dependencies
}

func (p *Parser) resolveDepManagement(props map[string]string, depManagement []pomDependency) []pomDependency {
	var newDepManagement, imports []pomDependency
	for _, dep := range depManagement {
		// cf. https://howtodoinjava.com/maven/maven-dependency-scopes/#import
		if dep.Scope == "import" {
			imports = append(imports, dep)
		} else {
			// Evaluate variables
			newDepManagement = append(newDepManagement, dep.Resolve(props, nil, nil))
		}
	}

	// Managed dependencies with a scope of "import" should be processed after other managed dependencies.
	// cf. https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#importing-dependencies
	for _, imp := range imports {
		art := newArtifact(imp.GroupID, imp.ArtifactID, imp.Version, nil, props)
		result, err := p.resolve(art, nil)
		if err != nil {
			continue
		}

		// We need to recursively check all nested depManagements,
		// so that we don't miss dependencies on nested depManagements with `Import` scope.
		newProps := utils.MergeMaps(props, result.properties)
		result.dependencyManagement = p.resolveDepManagement(newProps, result.dependencyManagement)
		for k, dd := range result.dependencyManagement {
			// Evaluate variables and overwrite dependencyManagement
			result.dependencyManagement[k] = dd.Resolve(newProps, nil, nil)
		}
		newDepManagement = p.mergeDependencyManagements(newDepManagement, result.dependencyManagement)
	}
	return newDepManagement
}

func (p *Parser) mergeDependencies(parent, child []artifact, exclusions map[string]struct{}) []artifact {
	var deps []artifact
	unique := make(map[string]struct{})

	for _, d := range append(child, parent...) {
		if excludeDep(exclusions, d) {
			continue
		}
		if _, ok := unique[d.Name()]; ok {
			continue
		}
		unique[d.Name()] = struct{}{}
		deps = append(deps, d)
	}

	return deps
}

func excludeDep(exclusions map[string]struct{}, art artifact) bool {
	if _, ok := exclusions[art.Name()]; ok {
		return true
	}
	// Maven can use "*" in GroupID and ArtifactID fields to exclude dependencies
	// https://maven.apache.org/pom.html#exclusions
	for exlusion := range exclusions {
		// exclusion format - "<groupID>:<artifactID>"
		e := strings.Split(exlusion, ":")
		if (e[0] == art.GroupID || e[0] == "*") && (e[1] == art.ArtifactID || e[1] == "*") {
			return true
		}
	}
	return false
}

func (p *Parser) parseParent(currentPath string, parent pomParent, rootDepManagement []pomDependency) (analysisResult, error) {
	// Pass nil properties so that variables in <parent> are not evaluated.
	target := newArtifact(parent.GroupId, parent.ArtifactId, parent.Version, nil, nil)
	// if version is property (e.g. ${revision}) - we still need to parse this pom
	if target.IsEmpty() && !isProperty(parent.Version) {
		return analysisResult{}, nil
	}

	logger := p.logger.With("artifact", target.String())
	logger.Debug("Start parent")
	defer logger.Debug("Exit parent")

	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(target); result != nil {
		return *result, nil
	}

	parentPOM, err := p.retrieveParent(currentPath, parent.RelativePath, target)
	if err != nil {
		logger.Debug("Parent POM not found", log.Err(err))
	}

	result, err := p.analyze(parentPOM, analysisOptions{
		depManagement: rootDepManagement,
	})
	if err != nil {
		return analysisResult{}, xerrors.Errorf("analyze error: %w", err)
	}

	p.cache.put(target, result)

	return result, nil
}

func (p *Parser) retrieveParent(currentPath, relativePath string, target artifact) (*pom, error) {
	var errs error

	// Try relativePath
	if relativePath != "" {
		pom, err := p.tryRelativePath(target, currentPath, relativePath)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			return pom, nil
		}
	}

	// If not found, search the parent director
	pom, err := p.tryRelativePath(target, currentPath, "../pom.xml")
	if err != nil {
		errs = multierror.Append(errs, err)
	} else {
		return pom, nil
	}

	// If not found, search local/remote remoteRepositories
	pom, err = p.tryRepository(target.GroupID, target.ArtifactID, target.Version.String())
	if err != nil {
		errs = multierror.Append(errs, err)
	} else {
		return pom, nil
	}

	// Reaching here means the POM wasn't found
	return nil, errs
}

func (p *Parser) tryRelativePath(parentArtifact artifact, currentPath, relativePath string) (*pom, error) {
	pom, err := p.openRelativePom(currentPath, relativePath)
	if err != nil {
		return nil, err
	}

	// To avoid an infinite loop or parsing the wrong parent when using relatedPath or `../pom.xml`,
	// we need to compare GAV of `parentArtifact` (`parent` tag from base pom) and GAV of pom from `relativePath`.
	// See `compare ArtifactIDs for base and parent pom's` test for example.
	// But GroupID can be inherited from parent (`p.analyze` function is required to get the GroupID).
	// Version can contain a property (`p.analyze` function is required to get the GroupID).
	// So we can only match ArtifactID's.
	if pom.artifact().ArtifactID != parentArtifact.ArtifactID {
		return nil, xerrors.New("'parent.relativePath' points at wrong local POM")
	}
	result, err := p.analyze(pom, analysisOptions{})
	if err != nil {
		return nil, xerrors.Errorf("analyze error: %w", err)
	}

	if !parentArtifact.Equal(result.artifact) {
		return nil, xerrors.New("'parent.relativePath' points at wrong local POM")
	}

	return pom, nil
}

func (p *Parser) openRelativePom(currentPath, relativePath string) (*pom, error) {
	// e.g. child/pom.xml => child/
	dir := filepath.Dir(currentPath)

	// e.g. child + ../parent => parent/
	filePath := filepath.Join(dir, relativePath)

	isDir, err := isDirectory(filePath)
	if err != nil {
		return nil, err
	} else if isDir {
		// e.g. parent/ => parent/pom.xml
		filePath = filepath.Join(filePath, "pom.xml")
	}

	pom, err := p.openPom(filePath)
	if err != nil {
		return nil, xerrors.Errorf("failed to open %s: %w", filePath, err)
	}
	return pom, nil
}

func (p *Parser) openPom(filePath string) (*pom, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error (%s): %w", filePath, err)
	}
	defer f.Close()

	content, err := parsePom(f)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse the local POM: %w", err)
	}
	return &pom{
		filePath: filePath,
		content:  content,
	}, nil
}
func (p *Parser) tryRepository(groupID, artifactID, version string) (*pom, error) {
	if version == "" {
		return nil, xerrors.Errorf("Version missing for %s:%s", groupID, artifactID)
	}

	// Generate a proper path to the pom.xml
	// e.g. com.fasterxml.jackson.core, jackson-annotations, 2.10.0
	//      => com/fasterxml/jackson/core/jackson-annotations/2.10.0/jackson-annotations-2.10.0.pom
	paths := strings.Split(groupID, ".")
	paths = append(paths, artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, version))

	// Search local remoteRepositories
	loaded, err := p.loadPOMFromLocalRepository(paths)
	if err == nil {
		return loaded, nil
	}

	// Search remote remoteRepositories
	loaded, err = p.fetchPOMFromRemoteRepositories(paths, isSnapshot(version))
	if err == nil {
		return loaded, nil
	}

	return nil, xerrors.Errorf("%s:%s:%s was not found in local/remote repositories", groupID, artifactID, version)
}

func (p *Parser) loadPOMFromLocalRepository(paths []string) (*pom, error) {
	paths = append([]string{p.localRepository}, paths...)
	localPath := filepath.Join(paths...)

	return p.openPom(localPath)
}

func (p *Parser) fetchPOMFromRemoteRepositories(paths []string, snapshot bool) (*pom, error) {
	// Do not try fetching pom.xml from remote repositories in offline mode
	if p.offline {
		p.logger.Debug("Fetching the remote pom.xml is skipped")
		return nil, xerrors.New("offline mode")
	}

	remoteRepos := p.releaseRemoteRepos
	// Maven uses only snapshot repos for snapshot artifacts
	if snapshot {
		remoteRepos = p.snapshotRemoteRepos
	}

	// try all remoteRepositories
	for _, repo := range remoteRepos {
		repoPaths := slices.Clone(paths) // Clone slice to avoid overwriting last element of `paths`
		if snapshot {
			pomFileName, err := p.fetchPomFileNameFromMavenMetadata(repo, repoPaths)
			if err != nil {
				return nil, xerrors.Errorf("fetch maven-metadata.xml error: %w", err)
			}
			// Use file name from `maven-metadata.xml` if it exists
			if pomFileName != "" {
				repoPaths[len(repoPaths)-1] = pomFileName
			}
		}
		fetched, err := p.fetchPOMFromRemoteRepository(repo, repoPaths)
		if err != nil {
			return nil, xerrors.Errorf("fetch repository error: %w", err)
		} else if fetched == nil {
			continue
		}
		return fetched, nil
	}
	return nil, xerrors.Errorf("the POM was not found in remote remoteRepositories")
}

func (p *Parser) remoteRepoRequest(repo string, paths []string) (*http.Request, error) {
	repoURL, err := url.Parse(repo)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse URL: %w", err)
	}

	paths = append([]string{repoURL.Path}, paths...)
	repoURL.Path = path.Join(paths...)

	req, err := http.NewRequest("GET", repoURL.String(), http.NoBody)
	if err != nil {
		return nil, xerrors.Errorf("unable to create HTTP request: %w", err)
	}
	if repoURL.User != nil {
		password, _ := repoURL.User.Password()
		req.SetBasicAuth(repoURL.User.Username(), password)
	}

	return req, nil
}

// performs an HTTP request with caching support
func (p *Parser) cachedHTTPRequest(req *http.Request, path string) ([]byte, int, error) {
	url := req.URL.String()

	// Try to get from cache first
	if entry, err := p.mavenHttpCache.get(path); err != nil {
		p.logger.Debug("Cache read error", log.String("url", url), log.String("path", path), log.Err(err))
	} else if entry != nil {
		p.logger.Debug("Cache hit", log.String("url", url), log.String("path", path))
		return entry.Data, entry.StatusCode, nil
	}

	p.logger.Debug("Cache miss, making HTTP request", log.String("url", url), log.String("path", path))

	var resp *http.Response
	var err error
	var statusCode int = 0
	var data = []byte{}
	var headers = make(map[string][]string)

	if p.mavenHttpCache.isDomainBlocklisted(req.URL.Host) {
		p.logger.Debug(
			fmt.Sprintf("Domain %s is blocklisted, assuming 404", req.URL.Host),
		)
		return nil, http.StatusNotFound, nil
	} else {
		// Make HTTP request
		client := &http.Client{}
		resp, err = client.Do(req)

		// HTTP request was made successfully (doesn't mean it was a 2xx, just that the client did not return an error)
		if err == nil {
			defer resp.Body.Close()

			statusCode = resp.StatusCode

			// Read response body
			data, err = io.ReadAll(resp.Body)

			if err != nil {
				return nil, statusCode, err
			}

			for k, v := range resp.Header {
				headers[k] = v
			}
		} else {
			// Error when making HTTP request
			p.logger.Debug("HTTP error", log.String("url", url), log.String("path", path), log.Err(err))

			if strings.Contains(err.Error(), "i/o timeout") {
				p.mavenHttpCache.domainTimeouts[req.URL.Host]++

				p.logger.Debug(
					"I/O timeout, falling back to 404",
					log.Int(fmt.Sprintf("numTimeouts[%s]", req.URL.Host), p.mavenHttpCache.domainTimeouts[req.URL.Host]),
				)

				if p.mavenHttpCache.domainTimeouts[req.URL.Host] >= MaxDomainTimeouts {
					p.logger.Warn(
						fmt.Sprintf("Blocklisting domain %s due to too many timeouts", req.URL.Host),
					)

					err = p.mavenHttpCache.blocklistDomain(req.URL.Host)
				}

				return nil, http.StatusNotFound, err
			} else {
				return nil, statusCode, err
			}
		}
	}

	// Cache 2xx or 404 (we don't want to keep fetching artifacts that are not found via 404)
	if statusCode == http.StatusOK || statusCode == http.StatusNotFound {
		if cacheErr := p.mavenHttpCache.set(url, path, data, headers, statusCode); cacheErr != nil {
			p.logger.Debug("Failed to cache response", log.String("url", url), log.String("path", path), log.Err(cacheErr))
		} else {
			p.logger.Debug("Cached response", log.String("url", url), log.String("path", path))
		}
	} else {
		p.logger.Debug("Response not successful, no caching", log.String("url", url), log.String("path", path), log.Int("statusCode", statusCode))
	}

	return data, statusCode, nil
}

// fetchPomFileNameFromMavenMetadata fetches `maven-metadata.xml` file to detect file name of pom file.
func (p *Parser) fetchPomFileNameFromMavenMetadata(repo string, paths []string) (string, error) {
	// Overwrite pom file name to `maven-metadata.xml`
	mavenMetadataPaths := slices.Clone(paths[:len(paths)-1]) // Clone slice to avoid shadow overwriting last element of `paths`
	mavenMetadataPaths = append(mavenMetadataPaths, "maven-metadata.xml")

	req, err := p.remoteRepoRequest(repo, mavenMetadataPaths)
	if err != nil {
		p.logger.Debug("Unable to create request", log.String("repo", repo), log.Err(err))
		return "", nil
	}

	data, statusCode, err := p.cachedHTTPRequest(req, strings.Join(mavenMetadataPaths, "/"))
	if err != nil {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Err(err))
		return "", nil
	} else if statusCode != http.StatusOK {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Int("statusCode", statusCode))
		return "", nil
	}

	mavenMetadata, err := parseMavenMetadata(strings.NewReader(string(data)))
	if err != nil {
		return "", xerrors.Errorf("failed to parse maven-metadata.xml file: %w", err)
	}

	var pomFileName string
	for _, sv := range mavenMetadata.Versioning.SnapshotVersions {
		if sv.Extension == "pom" {
			// mavenMetadataPaths[len(mavenMetadataPaths)-3] is always artifactID
			pomFileName = fmt.Sprintf("%s-%s.pom", mavenMetadataPaths[len(mavenMetadataPaths)-3], sv.Value)
		}
	}

	return pomFileName, nil
}

func (p *Parser) fetchPOMFromRemoteRepository(repo string, paths []string) (*pom, error) {
	req, err := p.remoteRepoRequest(repo, paths)
	if err != nil {
		p.logger.Debug("Unable to create request", log.String("repo", repo), log.Err(err))
		return nil, nil
	}

	data, statusCode, err := p.cachedHTTPRequest(req, strings.Join(paths, "/"))
	if err != nil {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Err(err))
		return nil, nil
	} else if statusCode != http.StatusOK {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Int("statusCode", statusCode))
		return nil, nil
	}

	content, err := parsePom(strings.NewReader(string(data)))
	if err != nil {
		return nil, xerrors.Errorf("failed to parse the remote POM: %w", err)
	}

	return &pom{
		filePath: "", // from remote repositories
		content:  content,
	}, nil
}

func parsePom(r io.Reader) (*pomXML, error) {
	parsed := &pomXML{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(parsed); err != nil {
		return nil, xerrors.Errorf("xml decode error: %w", err)
	}
	return parsed, nil
}

func parseMavenMetadata(r io.Reader) (*Metadata, error) {
	parsed := &Metadata{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(parsed); err != nil {
		return nil, xerrors.Errorf("xml decode error: %w", err)
	}
	return parsed, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Pom, name, version)
}

// cf. https://github.com/apache/maven/blob/259404701402230299fe05ee889ecdf1c9dae816/maven-artifact/src/main/java/org/apache/maven/artifact/DefaultArtifact.java#L482-L486
func isSnapshot(ver string) bool {
	return strings.HasSuffix(ver, "SNAPSHOT") || ver == "LATEST"
}
