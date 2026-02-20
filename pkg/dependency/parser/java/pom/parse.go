package pom

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/samber/lo"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

type options struct {
	offline       bool
	defaultRepo   repository
	settingsRepos []repository
}

type option func(*options)

func WithOffline(offline bool) option {
	return func(opts *options) {
		opts.offline = offline
	}
}

func WithDefaultRepo(repoURL string, releaseEnabled, snapshotEnabled bool) option {
	return func(opts *options) {
		u, _ := url.Parse(repoURL)
		opts.defaultRepo = repository{
			url:             *u,
			releaseEnabled:  releaseEnabled,
			snapshotEnabled: snapshotEnabled,
		}
	}
}

func WithSettingsRepos(repoURLs []string, releaseEnabled, snapshotEnabled bool) option {
	return func(opts *options) {
		opts.settingsRepos = xslices.Map(repoURLs, func(repoURL string) repository {
			u, _ := url.Parse(repoURL)
			return repository{
				url:             *u,
				releaseEnabled:  releaseEnabled,
				snapshotEnabled: snapshotEnabled,
			}
		})
	}
}

type Parser struct {
	logger          *log.Logger
	rootPath        string
	cache           pomCache
	localRepository string
	remoteRepos     repositories
	offline         bool
	servers         []Server
	httpClient      *http.Client
}

func NewParser(filePath string, opts ...option) *Parser {
	o := &options{
		offline:     false,
		defaultRepo: mavenCentralRepo,
	}

	s := readSettings()
	o.settingsRepos = s.effectiveRepositories()
	localRepository := s.LocalRepository
	if localRepository == "" {
		homeDir, _ := os.UserHomeDir()
		localRepository = filepath.Join(homeDir, ".m2", "repository")
	}

	for _, opt := range opts {
		opt(o)
	}

	remoteRepos := repositories{
		defaultRepo: o.defaultRepo,
		settings:    o.settingsRepos,
	}

	var httpOpts xhttp.Options
	if len(s.Proxies) > 0 {
		httpOpts.Proxy = func(req *http.Request) (*url.URL, error) {
			protocol := req.URL.Scheme
			proxies := s.effectiveProxies(protocol, req.URL.Hostname())
			// No Maven proxy -> fallback to environment
			if len(proxies) == 0 {
				return http.ProxyFromEnvironment(req)
			}
			// proxy retrieves the first active proxy matching the requested protocol.
			// Maven evaluates proxies in order and uses the first one that matches,
			// allowing for protocol-specific proxy configuration (e.g., http, https).
			proxy := proxies[0]

			proxyURL := &url.URL{
				Scheme: proxy.Protocol,
				Host:   net.JoinHostPort(proxy.Host, proxy.Port),
			}
			if proxy.Username != "" && proxy.Password != "" {
				proxyURL.User = url.UserPassword(proxy.Username, proxy.Password)
			}
			return proxyURL, nil
		}
	}

	tr := xhttp.NewTransport(httpOpts)

	return &Parser{
		logger:          log.WithPrefix("pom"),
		rootPath:        filepath.Clean(filePath),
		cache:           newPOMCache(),
		localRepository: localRepository,
		remoteRepos:     remoteRepos,
		offline:         o.offline,
		servers:         s.Servers,
		httpClient: &http.Client{
			Transport: tr.Build(),
		},
	}
}

func (p *Parser) Parse(ctx context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	content, err := parsePom(r, true)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse POM: %w", err)
	}

	root := &pom{
		filePath: p.rootPath,
		content:  content,
	}

	// Analyze root POM
	result, err := p.analyze(ctx, root, analysisOptions{
		rootFilePath: p.rootPath,
	})
	if err != nil {
		return nil, nil, xerrors.Errorf("analyze error (%s): %w", p.rootPath, err)
	}

	// Cache root POM
	p.cache.put(result.artifact, result)

	rootArt := result.artifact
	rootArt.Relationship = ftypes.RelationshipRoot

	return p.parseRoot(ctx, rootArt, set.New[string]())
}

// nolint: gocyclo
func (p *Parser) parseRoot(ctx context.Context, root artifact, uniqModules set.Set[string]) ([]ftypes.Package, []ftypes.Dependency, error) {
	if root.RootFilePath == "" {
		return nil, nil, xerrors.New("root file path is required for package ID generation")
	}

	// Prepare a queue for dependencies
	queue := newArtifactQueue()

	// Enqueue root POM
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
			id := packageID(art.Name(), art.Version.String(), art.RootFilePath)
			if uniqModules.Contains(id) {
				continue
			}
			uniqModules.Append(id)

			modulePkgs, moduleDeps, err := p.parseRoot(ctx, art, uniqModules)
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
			if uniqueArt.Relationship == ftypes.RelationshipRoot ||
				uniqueArt.Relationship == ftypes.RelationshipWorkspace ||
				uniqueArt.Relationship == ftypes.RelationshipDirect {
				art.Relationship = uniqueArt.Relationship
			}
			// We don't need to overwrite dependency location for hard links
			if uniqueArt.Locations != nil {
				art.Locations = uniqueArt.Locations
			}
		}

		result, err := p.resolve(ctx, art, rootDepManagement)
		if err != nil {
			return nil, nil, xerrors.Errorf("resolve error (%s): %w", art, err)
		}

		if art.Relationship == ftypes.RelationshipRoot || art.Relationship == ftypes.RelationshipWorkspace {
			// Managed dependencies in the root POM affect transitive dependencies
			rootDepManagement, err = p.resolveDepManagement(ctx, result.properties, result.dependencyManagement)
			if err != nil {
				return nil, nil, xerrors.Errorf("unable to resolve dep management: %w", err)
			}

			// mark its dependencies as "direct"
			result.dependencies = xslices.Map(result.dependencies, func(dep artifact) artifact {
				dep.Relationship = ftypes.RelationshipDirect
				return dep
			})
		}

		// Parse, cache, and enqueue modules.
		for _, relativePath := range result.modules {
			moduleArtifact, err := p.parseModule(ctx, result.filePath, relativePath, root.Repositories)
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
			dependsOn := xslices.Map(result.dependencies, func(a artifact) string {
				return a.Name()
			})
			uniqDeps[packageID(art.Name(), art.Version.String(), root.RootFilePath)] = dependsOn
		}
	}

	// Convert to []ftypes.Package and []ftypes.Dependency
	for name, art := range uniqArtifacts {
		pkg := ftypes.Package{
			ID:           packageID(name, art.Version.String(), root.RootFilePath),
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
			return packageID(dependOnName, ver, root.RootFilePath), ver != ""
		})

		// `mvn` shows modules separately from the root package and does not show module nesting.
		// So we can add all modules as dependencies of root package.
		if art.Relationship == ftypes.RelationshipRoot {
			dependsOn = append(dependsOn, uniqModules.Items()...)
		}

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

func (p *Parser) parseModule(ctx context.Context, currentPath, relativePath string, repos []repository) (artifact, error) {
	// modulePath: "root/" + "module/" => "root/module"
	module, err := p.openRelativePom(currentPath, relativePath)
	if err != nil {
		return artifact{}, xerrors.Errorf("unable to open the relative path: %w", err)
	}

	result, err := p.analyze(ctx, module, analysisOptions{
		rootFilePath: module.filePath,
		repositories: repos,
	})
	if err != nil {
		return artifact{}, xerrors.Errorf("analyze error: %w", err)
	}

	moduleArtifact := module.artifact()
	moduleArtifact.Module = true
	moduleArtifact.RootFilePath = module.filePath
	moduleArtifact.Relationship = ftypes.RelationshipWorkspace

	p.cache.put(moduleArtifact, result)

	return moduleArtifact, nil
}

func (p *Parser) resolve(ctx context.Context, art artifact, rootDepManagement []pomDependency) (analysisResult, error) {
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
	pomContent, err := p.tryRepository(ctx, art.GroupID, art.ArtifactID, art.Version.String(), art.Repositories)
	if err != nil {
		if shouldReturnError(err) {
			return analysisResult{}, err
		}
		p.logger.Debug("Repository error", log.Err(err))
	}

	result, err := p.analyze(ctx, pomContent, analysisOptions{
		exclusions:    art.Exclusions,
		depManagement: rootDepManagement,
		rootFilePath:  art.RootFilePath,
		repositories:  art.Repositories,
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
	exclusions    set.Set[string]
	depManagement []pomDependency // from the root POM
	rootFilePath  string          // File path of the root POM or module POM
	repositories  []repository    // Repositories inherited from parent
}

func (p *Parser) analyze(ctx context.Context, pom *pom, opts analysisOptions) (analysisResult, error) {
	if pom.nil() {
		return analysisResult{}, nil
	}
	if opts.exclusions == nil {
		opts.exclusions = set.New[string]()
	}

	// Get repositories from current POM and merge with inherited ones
	pomRepos := pom.repositories(p.servers)
	opts.repositories = lo.UniqBy(append(pomRepos, opts.repositories...), func(r repository) url.URL {
		return r.url
	})

	// Resolve parent POM
	// TODO handle repos from parents
	if err := p.resolveParent(ctx, pom, opts.repositories); err != nil {
		return analysisResult{}, xerrors.Errorf("pom resolve error: %w", err)
	}

	// Resolve dependencies
	props := pom.properties()
	depManagement := pom.content.DependencyManagement.Dependencies.Dependency
	deps, err := p.parseDependencies(ctx, pom.content.Dependencies.Dependency, props, depManagement, opts)
	if err != nil {
		return analysisResult{}, xerrors.Errorf("unable to parse dependencies: %w", err)
	}
	deps = p.filterDependencies(deps, opts.exclusions)

	art := pom.artifact()
	art.RootFilePath = opts.rootFilePath
	art.Repositories = opts.repositories

	return analysisResult{
		filePath:             pom.filePath,
		artifact:             art,
		dependencies:         deps,
		dependencyManagement: depManagement,
		properties:           props,
		modules:              pom.content.Modules.Module,
	}, nil
}

// resolveParent resolves its parent POMs and inherits properties, dependencies, and dependencyManagement.
func (p *Parser) resolveParent(ctx context.Context, pom *pom, pomRepos []repository) error {
	if pom.nil() {
		return nil
	}

	// Parse parent POM
	parent, err := p.parseParent(ctx, pom.filePath, pom.content.Parent, pomRepos)
	if err != nil {
		return xerrors.Errorf("parent error: %w", err)
	}

	// Inherit values/properties from parent
	pom.inherit(parent)

	// Merge properties
	pom.content.Properties = p.mergeProperties(pom.content.Properties, parent.content.Properties)

	// Merge dependencyManagement with the following priority:
	// 1. Managed dependencies from this POM
	// 2. Managed dependencies from parent of this POM
	pom.content.DependencyManagement.Dependencies.Dependency = p.mergeDependencyManagements(
		pom.content.DependencyManagement.Dependencies.Dependency,
		parent.content.DependencyManagement.Dependencies.Dependency)

	// Merge dependencies
	pom.content.Dependencies.Dependency = p.mergeDependencies(
		pom.content.Dependencies.Dependency,
		parent.content.Dependencies.Dependency)

	return nil
}

func (p *Parser) mergeDependencyManagements(depManagements ...[]pomDependency) []pomDependency {
	uniq := set.New[string]()
	var depManagement []pomDependency
	// The preceding argument takes precedence.
	for _, dm := range depManagements {
		for _, dep := range dm {
			if uniq.Contains(dep.Name()) {
				continue
			}
			depManagement = append(depManagement, dep)
			uniq.Append(dep.Name())
		}
	}
	return depManagement
}

func (p *Parser) parseDependencies(ctx context.Context, deps []pomDependency, props map[string]string, depManagement []pomDependency,
	opts analysisOptions,
) ([]artifact, error) {
	// Imported POMs often have no dependencies, so dependencyManagement resolution can be skipped.
	if len(deps) == 0 {
		return nil, nil
	}

	var err error
	// Resolve dependencyManagement
	depManagement, err = p.resolveDepManagement(ctx, props, depManagement)
	if err != nil {
		return nil, xerrors.Errorf("unable to resolve dep management: %w", err)
	}

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
	return dependencies, nil
}

// resolveDepManagement resolves depManagement, including imported POMs.
// It returns resolved depManagement with variables evaluated.
// It continues to resolve even if an error occurs while resolving an imported POM,
// but it returns an error if a context is canceled or the deadline is exceeded.
func (p *Parser) resolveDepManagement(ctx context.Context, props map[string]string, depManagement []pomDependency) ([]pomDependency, error) {
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
		result, err := p.resolve(ctx, art, nil)
		if shouldReturnError(err) {
			return nil, err
		} else if err != nil {
			continue
		}

		// We need to recursively check all nested depManagements,
		// so that we don't miss dependencies on nested depManagements with `Import` scope.
		newProps := utils.MergeMaps(props, result.properties)
		result.dependencyManagement, err = p.resolveDepManagement(ctx, newProps, result.dependencyManagement)
		if err != nil {
			return nil, err
		}
		for k, dd := range result.dependencyManagement {
			// Evaluate variables and overwrite dependencyManagement
			result.dependencyManagement[k] = dd.Resolve(newProps, nil, nil)
		}
		newDepManagement = p.mergeDependencyManagements(newDepManagement, result.dependencyManagement)
	}
	return newDepManagement, nil
}

func (p *Parser) mergeProperties(child, parent properties) properties {
	return lo.Assign(parent, child)
}

func (p *Parser) mergeDependencies(child, parent []pomDependency) []pomDependency {
	return lo.UniqBy(append(child, parent...), func(d pomDependency) string {
		return d.Name()
	})
}

func (p *Parser) filterDependencies(artifacts []artifact, exclusions set.Set[string]) []artifact {
	return lo.Filter(artifacts, func(art artifact, _ int) bool {
		return !excludeDep(exclusions, art)
	})
}

func excludeDep(exclusions set.Set[string], art artifact) bool {
	if exclusions.Contains(art.Name()) {
		return true
	}
	// Maven can use "*" in GroupID and ArtifactID fields to exclude dependencies
	// https://maven.apache.org/pom.html#exclusions
	for exlusion := range exclusions.Iter() {
		// exclusion format - "<groupID>:<artifactID>"
		e := strings.Split(exlusion, ":")
		if (e[0] == art.GroupID || e[0] == "*") && (e[1] == art.ArtifactID || e[1] == "*") {
			return true
		}
	}
	return false
}

func (p *Parser) parseParent(ctx context.Context, currentPath string, parent pomParent, pomRepos []repository) (*pom, error) {
	// Pass nil properties so that variables in <parent> are not evaluated.
	target := newArtifact(parent.GroupId, parent.ArtifactId, parent.Version, nil, nil)
	// if version is property (e.g. ${revision}) - we still need to parse this pom
	if target.IsEmpty() && !isProperty(parent.Version) {
		return &pom{content: &pomXML{}}, nil
	}

	logger := p.logger.With("artifact", target.String())
	logger.Debug("Start parent")
	defer logger.Debug("Exit parent")

	parentPOM, err := p.retrieveParent(ctx, currentPath, parent.RelativePath, target, pomRepos)
	if err != nil {
		if shouldReturnError(err) {
			return nil, err
		}
		logger.Debug("Parent POM not found", log.Err(err))
		return &pom{content: &pomXML{}}, nil
	}

	if err = p.resolveParent(ctx, parentPOM, pomRepos); err != nil {
		return nil, xerrors.Errorf("parent pom resolve error: %w", err)
	}

	return parentPOM, nil
}

func (p *Parser) retrieveParent(ctx context.Context, currentPath, relativePath string, target artifact, pomRepos []repository) (*pom, error) {
	var errs error

	// Try relativePath
	if relativePath != "" {
		pom, err := p.tryRelativePath(ctx, target, currentPath, relativePath, pomRepos)
		if err == nil {
			return pom, nil
		}
		errs = multierror.Append(errs, err)
	}

	// If not found, search the parent director
	pom, err := p.tryRelativePath(ctx, target, currentPath, "../pom.xml", pomRepos)
	if err == nil {
		return pom, nil
	}
	errs = multierror.Append(errs, err)

	// If not found, search local/remote remoteRepositories
	pom, err = p.tryRepository(ctx, target.GroupID, target.ArtifactID, target.Version.String(), pomRepos)
	if err == nil {
		return pom, nil
	}
	errs = multierror.Append(errs, err)

	// Reaching here means the POM wasn't found
	return nil, errs
}

func (p *Parser) tryRelativePath(ctx context.Context, parentArtifact artifact, currentPath, relativePath string, pomRepos []repository) (*pom, error) {
	parsedPOM, err := p.openRelativePom(currentPath, relativePath)
	if err != nil {
		return nil, err
	}

	// To avoid an infinite loop or parsing the wrong parent when using relatedPath or `../pom.xml`,
	// we need to compare GAV of `parentArtifact` (`parent` tag from base pom) and GAV of pom from `relativePath`.
	// See `compare ArtifactIDs for base and parent pom's` test for example.
	// But GroupID can be inherited from parent (`p.analyze` function is required to get the GroupID).
	// Version can contain a property (`p.analyze` function is required to get the GroupID).
	// So we can only match ArtifactID's.
	if parsedPOM.artifact().ArtifactID != parentArtifact.ArtifactID {
		return nil, xerrors.New("'parent.relativePath' points at wrong local POM")
	}
	if err := p.resolveParent(ctx, parsedPOM, pomRepos); err != nil {
		return nil, xerrors.Errorf("analyze error: %w", err)
	}

	if !parentArtifact.Equal(parsedPOM.artifact()) {
		return nil, xerrors.New("'parent.relativePath' points at wrong local POM")
	}

	return parsedPOM, nil
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

	content, err := parsePom(f, false)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse the local POM: %w", err)
	}
	return &pom{
		filePath: filePath,
		content:  content,
	}, nil
}

func (p *Parser) tryRepository(ctx context.Context, groupID, artifactID, version string, pomRepos []repository) (*pom, error) {
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
	loaded, err = p.fetchPOMFromRemoteRepositories(ctx, paths, isSnapshot(version), pomRepos)
	if err == nil {
		return loaded, nil
		// We should return error if it's not "not found" error
	} else if shouldReturnError(err) {
		return nil, err
	}

	return nil, xerrors.Errorf("%s:%s:%s was not found in local/remote repositories", groupID, artifactID, version)
}

func (p *Parser) loadPOMFromLocalRepository(paths []string) (*pom, error) {
	paths = append([]string{p.localRepository}, paths...)
	localPath := filepath.Join(paths...)

	return p.openPom(localPath)
}

func (p *Parser) fetchPOMFromRemoteRepositories(ctx context.Context, paths []string, snapshot bool, pomRepos []repository) (*pom, error) {
	// Do not try fetching pom.xml from remote repositories in offline mode
	if p.offline {
		p.logger.Debug("Fetching the remote pom.xml is skipped")
		return nil, xerrors.New("offline mode")
	}

	// Try all remoteRepositories by following order:
	// 1. remoteRepositories from settings.xml
	// 2. remoteRepositories from pom.xml (passed as parameter)
	// 3. default remoteRepository (Maven Central for Release repository)
	for _, repo := range slices.Concat(p.remoteRepos.settings, pomRepos, []repository{p.remoteRepos.defaultRepo}) {
		// Skip Release only repositories for snapshot artifacts and vice versa
		if snapshot && !repo.snapshotEnabled || !snapshot && !repo.releaseEnabled {
			continue
		}

		repoPaths := slices.Clone(paths) // Clone slice to avoid overwriting last element of `paths`
		if snapshot {
			pomFileName, err := p.fetchPomFileNameFromMavenMetadata(ctx, repo.url, repoPaths)
			if err != nil {
				return nil, xerrors.Errorf("fetch maven-metadata.xml error: %w", err)
			}
			// Use file name from `maven-metadata.xml` if it exists
			if pomFileName != "" {
				repoPaths[len(repoPaths)-1] = pomFileName
			}
		}
		fetched, err := p.fetchPOMFromRemoteRepository(ctx, repo.url, repoPaths)
		if err != nil {
			return nil, xerrors.Errorf("fetch repository error: %w", err)
		} else if fetched == nil {
			continue
		}
		return fetched, nil
	}
	return nil, xerrors.Errorf("the POM was not found in remote remoteRepositories")
}

func (p *Parser) remoteRepoRequest(ctx context.Context, repoURL url.URL, paths []string) (*http.Request, error) {
	paths = append([]string{repoURL.Path}, paths...)
	repoURL.Path = path.Join(paths...)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repoURL.String(), http.NoBody)
	if err != nil {
		return nil, xerrors.Errorf("unable to create HTTP request: %w", err)
	}
	if repoURL.User != nil {
		password, _ := repoURL.User.Password()
		req.SetBasicAuth(repoURL.User.Username(), password)
	}

	return req, nil
}

// fetchPomFileNameFromMavenMetadata fetches `maven-metadata.xml` file to detect file name of pom file.
func (p *Parser) fetchPomFileNameFromMavenMetadata(ctx context.Context, repoURL url.URL, paths []string) (string, error) {
	// Overwrite pom file name to `maven-metadata.xml`
	mavenMetadataPaths := slices.Clone(paths[:len(paths)-1]) // Clone slice to avoid shadow overwriting last element of `paths`
	mavenMetadataPaths = append(mavenMetadataPaths, "maven-metadata.xml")

	req, err := p.remoteRepoRequest(ctx, repoURL, mavenMetadataPaths)
	if err != nil {
		p.logger.Debug("Unable to create request", log.String("repo", repoURL.Redacted()), log.Err(err))
		return "", nil
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		if shouldReturnError(err) {
			return "", err
		}
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.Redacted()), log.Err(err))
		return "", nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.Redacted()), log.Int("statusCode", resp.StatusCode))
		return "", nil
	}

	mavenMetadata, err := parseMavenMetadata(resp.Body)
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

func (p *Parser) fetchPOMFromRemoteRepository(ctx context.Context, repoURL url.URL, paths []string) (*pom, error) {
	req, err := p.remoteRepoRequest(ctx, repoURL, paths)
	if err != nil {
		p.logger.Debug("Unable to create request", log.String("repo", repoURL.Redacted()), log.Err(err))
		return nil, nil
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		if shouldReturnError(err) {
			return nil, err
		}
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.Redacted()), log.Err(err))
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.Redacted()), log.Int("statusCode", resp.StatusCode))
		return nil, nil
	}

	content, err := parsePom(resp.Body, false)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse the remote POM: %w", err)
	}

	return &pom{
		filePath: "", // from remote repositories
		content:  content,
	}, nil
}

func parsePom(r io.Reader, lineNumber bool) (*pomXML, error) {
	parsed := &pomXML{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(parsed); err != nil {
		return nil, xerrors.Errorf("xml decode error: %w", err)
	}
	if !lineNumber {
		for i := range parsed.Dependencies.Dependency {
			parsed.Dependencies.Dependency[i].StartLine = 0
			parsed.Dependencies.Dependency[i].EndLine = 0
		}
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

func packageID(name, version, pomFilePath string) string {
	gav := dependency.ID(ftypes.Pom, name, version)
	v := map[string]any{
		"gav":  gav,
		"path": filepath.ToSlash(pomFilePath),
	}
	h, err := hashstructure.Hash(v, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:         true,
		IgnoreZeroValue: true,
	})
	if err != nil {
		log.Warn("Failed to calculate hash", log.Err(err))
		return gav // fallback to GAV only
	}
	// Append 8-character hash suffix
	return fmt.Sprintf("%s::%s", gav, strconv.FormatUint(h, 16)[:8])
}

// cf. https://github.com/apache/maven/blob/259404701402230299fe05ee889ecdf1c9dae816/maven-artifact/src/main/java/org/apache/maven/artifact/DefaultArtifact.java#L482-L486
func isSnapshot(ver string) bool {
	return strings.HasSuffix(ver, "SNAPSHOT") || ver == "LATEST"
}

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
}

func shouldReturnError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}
