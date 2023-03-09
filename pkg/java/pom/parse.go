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
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

const (
	centralURL = "https://repo.maven.apache.org/maven2/"
)

type options struct {
	offline     bool
	remoteRepos []string
}

type option func(*options)

func WithOffline(offline bool) option {
	return func(opts *options) {
		opts.offline = offline
	}
}

func WithRemoteRepos(repos []string) option {
	return func(opts *options) {
		opts.remoteRepos = repos
	}
}

type parser struct {
	rootPath           string
	cache              pomCache
	localRepository    string
	remoteRepositories []string
	offline            bool
}

func NewParser(filePath string, opts ...option) types.Parser {
	o := &options{
		offline:     false,
		remoteRepos: []string{centralURL},
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

	return &parser{
		rootPath:           filepath.Clean(filePath),
		cache:              newPOMCache(),
		localRepository:    localRepository,
		remoteRepositories: o.remoteRepos,
		offline:            o.offline,
	}
}

func (p *parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	content, err := parsePom(r)
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

	return p.parseRoot(root.artifact())
}

func (p *parser) parseRoot(root artifact) ([]types.Library, []types.Dependency, error) {
	// Prepare a queue for dependencies
	queue := newArtifactQueue()

	// Enqueue root POM
	root.Root = true
	root.Module = false
	queue.enqueue(root)

	var (
		libs              []types.Library
		deps              []types.Dependency
		rootDepManagement []pomDependency
		uniqArtifacts     = map[string]version{}
	)

	// Iterate direct and transitive dependencies
	for !queue.IsEmpty() {
		art := queue.dequeue()

		// Modules should be handled separately so that they can have independent dependencies.
		// It means multi-module allows for duplicate dependencies.
		if art.Module {
			moduleLibs, moduleDeps, err := p.parseRoot(art)
			if err != nil {
				return nil, nil, err
			}
			libs = append(libs, moduleLibs...)
			if deps != nil {
				deps = append(deps, moduleDeps...)
			}
			continue
		}

		// For soft requirements, skip dependency resolution that has already been resolved.
		if v, ok := uniqArtifacts[art.Name()]; ok {
			if !v.shouldOverride(art.Version) {
				continue
			}
		}

		result, err := p.resolve(art, rootDepManagement)
		if err != nil {
			return nil, nil, xerrors.Errorf("resolve error (%s): %w", art, err)
		}

		if art.Root {
			// Managed dependencies in the root POM affect transitive dependencies
			rootDepManagement = p.resolveDepManagement(result.properties, result.dependencyManagement)
		}

		// Parse, cache, and enqueue modules.
		for _, relativePath := range result.modules {
			moduleArtifact, err := p.parseModule(result.filePath, relativePath)
			if err != nil {
				return nil, nil, xerrors.Errorf("module error (%s): %w", relativePath, err)
			}

			queue.enqueue(moduleArtifact)
		}

		// Resolve transitive dependencies later
		queue.enqueue(result.dependencies...)

		// Offline mode may be missing some fields.
		if !art.IsEmpty() {
			// Override the version
			uniqArtifacts[art.Name()] = art.Version
		}
	}

	// Convert to []types.Library
	for name, ver := range uniqArtifacts {
		libs = append(libs, types.Library{
			Name:    name,
			Version: ver.String(),
		})
	}

	return libs, deps, nil
}

func (p *parser) parseModule(currentPath, relativePath string) (artifact, error) {
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

	p.cache.put(moduleArtifact, result)

	return moduleArtifact, nil
}

func (p *parser) resolve(art artifact, rootDepManagement []pomDependency) (analysisResult, error) {
	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(art); result != nil {
		return *result, nil
	}

	log.Logger.Debugf("Resolving %s:%s:%s...", art.GroupID, art.ArtifactID, art.Version)
	pomContent, err := p.tryRepository(art.GroupID, art.ArtifactID, art.Version.String())
	if err != nil {
		log.Logger.Debug(err)
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
}

func (p *parser) analyze(pom *pom, opts analysisOptions) (analysisResult, error) {
	if pom == nil || pom.content == nil {
		return analysisResult{}, nil
	}

	// Update remoteRepositories
	p.remoteRepositories = utils.UniqueStrings(append(p.remoteRepositories, pom.repositories()...))

	// Parent
	parent, err := p.parseParent(pom.filePath, pom.content.Parent)
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
	deps := p.parseDependencies(pom.content.Dependencies.Dependency, props, depManagement, opts.depManagement, opts.exclusions)
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

func (p *parser) mergeDependencyManagements(depManagements ...[]pomDependency) []pomDependency {
	uniq := map[string]struct{}{}
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

func (p *parser) parseDependencies(deps []pomDependency, props map[string]string, depManagement, rootDepManagement []pomDependency,
	exclusions map[string]struct{}) []artifact {
	// Imported POMs often have no dependencies, so dependencyManagement resolution can be skipped.
	if len(deps) == 0 {
		return nil
	}

	// Resolve dependencyManagement
	depManagement = p.resolveDepManagement(props, depManagement)

	var dependencies []artifact
	for _, d := range deps {
		// Resolve dependencies
		d = d.Resolve(props, depManagement, rootDepManagement)

		if (d.Scope != "" && d.Scope != "compile") || d.Optional {
			continue
		}
		dependencies = append(dependencies, d.ToArtifact(exclusions))
	}
	return dependencies
}

func (p *parser) resolveDepManagement(props map[string]string, depManagement []pomDependency) []pomDependency {
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
		art := newArtifact(imp.GroupID, imp.ArtifactID, imp.Version, props)
		result, err := p.resolve(art, nil)
		if err != nil {
			continue
		}
		for k, dd := range result.dependencyManagement {
			// Evaluate variables and overwrite dependencyManagement
			result.dependencyManagement[k] = dd.Resolve(result.properties, nil, nil)
		}
		newDepManagement = p.mergeDependencyManagements(newDepManagement, result.dependencyManagement)
	}
	return newDepManagement
}

func (p *parser) mergeDependencies(parent, child []artifact, exclusions map[string]struct{}) []artifact {
	var deps []artifact
	unique := map[string]struct{}{}

	for _, d := range append(parent, child...) {
		if _, ok := exclusions[d.Name()]; ok {
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

func (p *parser) parseParent(currentPath string, parent pomParent) (analysisResult, error) {
	// Pass nil properties so that variables in <parent> are not evaluated.
	target := newArtifact(parent.GroupId, parent.ArtifactId, parent.Version, nil)
	if target.IsEmpty() {
		return analysisResult{}, nil
	}
	log.Logger.Debugf("Start parent: %s", target.String())
	defer func() {
		log.Logger.Debugf("Exit parent: %s", target.String())
	}()

	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(target); result != nil {
		return *result, nil
	}

	parentPOM, err := p.retrieveParent(currentPath, parent.RelativePath, target)
	if err != nil {
		log.Logger.Debugf("parent POM not found: %s", err)
	}

	result, err := p.analyze(parentPOM, analysisOptions{})
	if err != nil {
		return analysisResult{}, xerrors.Errorf("analyze error: %w", err)
	}

	p.cache.put(target, result)

	return result, nil
}

func (p *parser) retrieveParent(currentPath, relativePath string, target artifact) (*pom, error) {
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

func (p *parser) tryRelativePath(parentArtifact artifact, currentPath, relativePath string) (*pom, error) {
	pom, err := p.openRelativePom(currentPath, relativePath)
	if err != nil {
		return nil, err
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

func (p *parser) openRelativePom(currentPath, relativePath string) (*pom, error) {
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

func (p *parser) openPom(filePath string) (*pom, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error (%s): %w", filePath, err)
	}

	content, err := parsePom(f)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse the local POM: %w", err)
	}
	return &pom{
		filePath: filePath,
		content:  content,
	}, nil
}
func (p *parser) tryRepository(groupID, artifactID, version string) (*pom, error) {
	// Generate a proper path to the pom.xml
	// e.g. com.fasterxml.jackson.core, jackson-annotations, 2.10.0
	//      => com/fasterxml/jackson/core/jackson-annotations/2.10.0/jackson-annotations-2.10.0.pom
	paths := strings.Split(groupID, ".")
	paths = append(paths, artifactID, version)
	paths = append(paths, fmt.Sprintf("%s-%s.pom", artifactID, version))

	// Search local remoteRepositories
	loaded, err := p.loadPOMFromLocalRepository(paths)
	if err == nil {
		return loaded, nil
	}

	// Search remote remoteRepositories
	loaded, err = p.fetchPOMFromRemoteRepository(paths)
	if err == nil {
		return loaded, nil
	}

	return nil, xerrors.Errorf("%s:%s:%s was not found in local/remote repositories", groupID, artifactID, version)
}

func (p *parser) loadPOMFromLocalRepository(paths []string) (*pom, error) {
	paths = append([]string{p.localRepository}, paths...)
	localPath := filepath.Join(paths...)

	return p.openPom(localPath)
}

func (p *parser) fetchPOMFromRemoteRepository(paths []string) (*pom, error) {
	// Do not try fetching pom.xml from remote repositories in offline mode
	if p.offline {
		log.Logger.Debug("Fetching the remote pom.xml is skipped")
		return nil, xerrors.New("offline mode")
	}

	// try all remoteRepositories
	for _, repo := range p.remoteRepositories {
		repoURL, err := url.Parse(repo)
		if err != nil {
			continue
		}

		paths = append([]string{repoURL.Path}, paths...)
		repoURL.Path = path.Join(paths...)

		resp, err := http.Get(repoURL.String())
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		content, err := parsePom(resp.Body)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse the remote POM: %w", err)
		}

		return &pom{
			filePath: "", // from remote repositories
			content:  content,
		}, nil
	}
	return nil, xerrors.Errorf("the POM was not found in remote remoteRepositories")
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
