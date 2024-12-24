package pom

import (
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
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	centralURL = "https://repo.maven.apache.org/maven2/"
)

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
	localRepository     string
	releaseRemoteRepos  []string
	snapshotRemoteRepos []string
	offline             bool
	servers             []Server
}

func NewParser(filePath string, opts ...option) *Parser {
	o := &options{
		offline:            false,
		releaseRemoteRepos: []string{centralURL}, // Maven doesn't use central repository for snapshot dependencies
	}

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
		logger:              log.WithPrefix("pom"),
		rootPath:            filepath.Clean(filePath),
		cache:               newPOMCache(),
		localRepository:     localRepository,
		releaseRemoteRepos:  o.releaseRemoteRepos,
		snapshotRemoteRepos: o.snapshotRemoteRepos,
		offline:             o.offline,
		servers:             s.Servers,
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	content, err := parsePom(r, true)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse POM: %w", err)
	}

	root := &pom{
		filePath: p.rootPath,
		content:  content,
	}

	// Analyze root POM
	result, err := p.analyze(root, analysisOptions{})
	if err != nil {
		return nil, nil, xerrors.Errorf("analyze error (%s): %w", p.rootPath, err)
	}

	// Cache root POM
	p.cache.put(result.artifact, result)

	rootArt := root.artifact()
	rootArt.Relationship = ftypes.RelationshipRoot

	return p.parseRoot(rootArt, set.New[string]())
}

// nolint: gocyclo
func (p *Parser) parseRoot(root artifact, uniqModules set.Set[string]) ([]ftypes.Package, []ftypes.Dependency, error) {
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
			if uniqModules.Contains(art.String()) {
				continue
			}
			uniqModules.Append(art.String())

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

		result, err := p.resolve(art, rootDepManagement)
		if err != nil {
			return nil, nil, xerrors.Errorf("resolve error (%s): %w", art, err)
		}

		if art.Relationship == ftypes.RelationshipRoot || art.Relationship == ftypes.RelationshipWorkspace {
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
	moduleArtifact.Module = true
	moduleArtifact.Relationship = ftypes.RelationshipWorkspace

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
	exclusions    set.Set[string]
	depManagement []pomDependency // from the root POM
}

func (p *Parser) analyze(pom *pom, opts analysisOptions) (analysisResult, error) {
	if pom.nil() {
		return analysisResult{}, nil
	}
	if opts.exclusions == nil {
		opts.exclusions = set.New[string]()
	}
	// Update remoteRepositories
	pomReleaseRemoteRepos, pomSnapshotRemoteRepos := pom.repositories(p.servers)
	p.releaseRemoteRepos = lo.Uniq(append(pomReleaseRemoteRepos, p.releaseRemoteRepos...))
	p.snapshotRemoteRepos = lo.Uniq(append(pomSnapshotRemoteRepos, p.snapshotRemoteRepos...))

	// Resolve parent POM
	if err := p.resolveParent(pom); err != nil {
		return analysisResult{}, xerrors.Errorf("pom resolve error: %w", err)
	}

	// Resolve dependencies
	props := pom.properties()
	depManagement := pom.content.DependencyManagement.Dependencies.Dependency
	deps := p.parseDependencies(pom.content.Dependencies.Dependency, props, depManagement, opts)
	deps = p.filterDependencies(deps, opts.exclusions)

	return analysisResult{
		filePath:             pom.filePath,
		artifact:             pom.artifact(),
		dependencies:         deps,
		dependencyManagement: depManagement,
		properties:           props,
		modules:              pom.content.Modules.Module,
	}, nil
}

// resolveParent resolves its parent POMs and inherits properties, dependencies, and dependencyManagement.
func (p *Parser) resolveParent(pom *pom) error {
	if pom.nil() {
		return nil
	}

	// Parse parent POM
	parent, err := p.parseParent(pom.filePath, pom.content.Parent)
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

func (p *Parser) parseParent(currentPath string, parent pomParent) (*pom, error) {
	// Pass nil properties so that variables in <parent> are not evaluated.
	target := newArtifact(parent.GroupId, parent.ArtifactId, parent.Version, nil, nil)
	// if version is property (e.g. ${revision}) - we still need to parse this pom
	if target.IsEmpty() && !isProperty(parent.Version) {
		return &pom{content: &pomXML{}}, nil
	}

	logger := p.logger.With("artifact", target.String())
	logger.Debug("Start parent")
	defer logger.Debug("Exit parent")

	parentPOM, err := p.retrieveParent(currentPath, parent.RelativePath, target)
	if err != nil {
		logger.Debug("Parent POM not found", log.Err(err))
		return &pom{content: &pomXML{}}, nil
	}

	if err = p.resolveParent(parentPOM); err != nil {
		return nil, xerrors.Errorf("parent pom resolve error: %w", err)
	}

	return parentPOM, nil
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
	if err := p.resolveParent(parsedPOM); err != nil {
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

	req, err := http.NewRequest(http.MethodGet, repoURL.String(), http.NoBody)
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
func (p *Parser) fetchPomFileNameFromMavenMetadata(repo string, paths []string) (string, error) {
	// Overwrite pom file name to `maven-metadata.xml`
	mavenMetadataPaths := slices.Clone(paths[:len(paths)-1]) // Clone slice to avoid shadow overwriting last element of `paths`
	mavenMetadataPaths = append(mavenMetadataPaths, "maven-metadata.xml")

	req, err := p.remoteRepoRequest(repo, mavenMetadataPaths)
	if err != nil {
		p.logger.Debug("Unable to create request", log.String("repo", repo), log.Err(err))
		return "", nil
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Err(err))
		return "", nil
	} else if resp.StatusCode != http.StatusOK {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Int("statusCode", resp.StatusCode))
		return "", nil
	}
	defer resp.Body.Close()

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

func (p *Parser) fetchPOMFromRemoteRepository(repo string, paths []string) (*pom, error) {
	req, err := p.remoteRepoRequest(repo, paths)
	if err != nil {
		p.logger.Debug("Unable to create request", log.String("repo", repo), log.Err(err))
		return nil, nil
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Err(err))
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		p.logger.Debug("Failed to fetch", log.String("url", req.URL.String()), log.Int("statusCode", resp.StatusCode))
		return nil, nil
	}
	defer resp.Body.Close()

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

func packageID(name, version string) string {
	return dependency.ID(ftypes.Pom, name, version)
}

// cf. https://github.com/apache/maven/blob/259404701402230299fe05ee889ecdf1c9dae816/maven-artifact/src/main/java/org/apache/maven/artifact/DefaultArtifact.java#L482-L486
func isSnapshot(ver string) bool {
	return strings.HasSuffix(ver, "SNAPSHOT") || ver == "LATEST"
}
