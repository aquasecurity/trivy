package eval

import (
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/apparentlymart/go-versions/versions"
	"github.com/hashicorp/go-getter"
	"github.com/hashicorp/go-slug/sourceaddrs"
	regaddr "github.com/hashicorp/terraform-registry-address"
)

var rootSrc = sourceaddrs.MustParseSource("./").(sourceaddrs.LocalSource)

type PackageFether interface {
	Fetch(ctx context.Context, sourceType string, url *url.URL, targetDir string) error
}

type RegistryClient interface {
	ModulePackageVersions(ctx context.Context, pkgAddr regaddr.ModulePackage) (ModulePackageVersionsResponse, error)
	ModulePackageSourceAddr(ctx context.Context, pkgAddr regaddr.ModulePackage, version versions.Version) (ModulePackageSourceAddrResponse, error)
}

type ModulePackageVersionsResponse struct {
	Versions []ModulePackageInfo `json:"versions"`
}

type ModulePackageInfo struct {
	Version versions.Version `json:"version"`
}

type ModulePackageSourceAddrResponse struct {
	SourceAddr sourceaddrs.RemoteSource
}

type ModuleResolver struct {
	targetDir  string
	pkgFetcher PackageFether
	regClient  RegistryClient
}

func NewModuleResolver(targetDir string, pkgFetcher PackageFether, regClient RegistryClient) *ModuleResolver {
	return &ModuleResolver{
		targetDir:  targetDir,
		pkgFetcher: pkgFetcher,
		regClient:  regClient,
	}
}

func (r *ModuleResolver) Resolve(ctx context.Context, fsys fs.FS, root string) (*ModuleConfig, error) {
	fakeCall := ModuleCall{
		Name:   "root",
		Source: rootSrc,
		FS:     fsys,
		Path:   root,
	}

	rootCfg, err := r.resolveChildren(ctx, &fakeCall)
	if err != nil {
		return rootCfg, err
	}
	rootCfg.Name = "root"
	rootCfg.FS = fsys
	rootCfg.Dir = root

	return rootCfg, nil
}

func (r *ModuleResolver) resolveChildren(ctx context.Context, mc *ModuleCall) (*ModuleConfig, error) {
	mod, err := r.loadModule(ctx, mc)
	if err != nil {
		return nil, err
	}

	for _, childMc := range mod.ModuleCalls {
		child, err := r.resolveChildren(ctx, childMc)
		if err != nil {
			return nil, err
		}
		child.Parent = mod
		child.Name = childMc.Name
		child.FS = childMc.FS
		child.Dir = childMc.Path
		child.Block = childMc.Config
		mod.Children = append(mod.Children, child)
	}
	return mod, nil

}

func (r *ModuleResolver) loadModule(ctx context.Context, mc *ModuleCall) (*ModuleConfig, error) {
	log.Printf("Resolve module from %s", mc.Source.String())
	switch src := mc.Source.(type) {
	case sourceaddrs.LocalSource:
		return r.resolveLocal(ctx, mc.FS, path.Join(mc.Path, src.RelativePath()))
	case sourceaddrs.RegistrySource:
		var selectedVers versions.Set
		if mc.Version.Same(versions.Unspecified) {
			selectedVers = versions.All
		} else {
			selectedVers = versions.Only(mc.Version)
			if fsys, ok := r.checkCache(src.Package().String(), mc.Version.String()); ok {
				log.Printf("Module %s found in cache", src.String())
				return r.resolveLocal(ctx, fsys, cmp.Or(src.SubPath(), "."))
			}
		}
		return r.resolveRegistry(ctx, src, selectedVers)
	case sourceaddrs.RemoteSource:
		return r.resolveRemote(ctx, src)
	default:
		return nil, fmt.Errorf("unsupported source: %s", src.String())
	}
}

func (r *ModuleResolver) resolveLocal(_ context.Context, fsys fs.FS, dir string) (*ModuleConfig, error) {
	p := NewParser()
	cfg, err := p.ParseDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	log.Printf("Module %s loaded from %v", dir, fsys)
	return cfg, nil
}

func (r *ModuleResolver) resolveRegistry(ctx context.Context, src sourceaddrs.RegistrySource, selectedVersions versions.Set) (*ModuleConfig, error) {
	versionsResponse, err := r.regClient.ModulePackageVersions(ctx, src.Package())
	if err != nil {
		return nil, err
	}

	versionsList := make(versions.List, 0, len(versionsResponse.Versions))
	for _, el := range versionsResponse.Versions {
		versionsList = append(versionsList, el.Version)
	}
	versionsList.Sort()

	selectedVersion := versionsList.NewestInSet(selectedVersions)
	if selectedVersion == versions.Unspecified {
		return nil, fmt.Errorf("no available version of %s matches the specified version constraint",
			src.Package().String())
	}

	locationResponse, err := r.regClient.ModulePackageSourceAddr(ctx, src.Package(), selectedVersion)
	if err != nil {
		return nil, err
	}

	remoteSrc := src.FinalSourceAddr(locationResponse.SourceAddr)
	return r.resolveRemote(ctx, remoteSrc)
}

func (r *ModuleResolver) resolveRemote(ctx context.Context, src sourceaddrs.RemoteSource) (*ModuleConfig, error) {
	log.Printf("Resolve %s module", src.String())
	modDir := r.dirName(src.String(), "")
	finalDir := filepath.Join(r.targetDir, modDir)
	pkg := src.Package()

	if fsys, ok := r.checkCache(pkg.String(), ""); ok {
		log.Printf("Module %s found in cache", src.String())
		return r.resolveLocal(ctx, fsys, cmp.Or(src.SubPath(), "."))
	}

	workDir, err := os.MkdirTemp(".", ".trivy-tfmod-")
	if err != nil {
		return nil, err
	}
	log.Printf("Load remote module %s into %s", pkg.String(), workDir)

	if err := r.pkgFetcher.Fetch(ctx, pkg.SourceType(), pkg.URL(), workDir); err != nil {
		return nil, err
	}
	log.Printf("Remote module %s loaded", pkg.String())

	if err := os.Rename(workDir, finalDir); err != nil {
		return nil, err
	}
	log.Printf("Remote module %s moved into %s", pkg.String(), finalDir)
	return r.resolveLocal(ctx, os.DirFS(r.targetDir), filepath.Join(modDir, src.SubPath()))
}

func (r *ModuleResolver) dirName(src, ver string) string {
	hash := md5.Sum([]byte(src + ":" + ver)) // #nosec
	return hex.EncodeToString(hash[:])
}

func (r *ModuleResolver) checkCache(pkg string, ver string) (fs.FS, bool) {
	modDir := r.dirName(pkg, ver)
	finalDir := filepath.Join(r.targetDir, modDir)
	if _, err := os.Stat(finalDir); err == nil {
		return os.DirFS(finalDir), true
	}
	return nil, false
}

type packageFetcher struct {
	workingDir string
}

func (f *packageFetcher) Fetch(ctx context.Context, sourceType string, url *url.URL, targetDir string) error {
	if err := os.RemoveAll(targetDir); err != nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(targetDir), 0o750); err != nil {
		return err
	}
	getter.Getters["file"] = &getter.FileGetter{Copy: true}
	client := &getter.Client{
		Ctx:     ctx,
		Src:     sourceType + "::" + url.String(),
		Dst:     targetDir,
		Pwd:     f.workingDir,
		Getters: getter.Getters,
		Mode:    getter.ClientModeAny,
	}

	if err := client.Get(); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	return nil
}

type registryClient struct {
	client *http.Client
	logger *slog.Logger
}

func (c *registryClient) ModulePackageVersions(ctx context.Context, pkgAddr regaddr.ModulePackage) (ModulePackageVersionsResponse, error) {
	versionUrl := fmt.Sprintf("https://%s/v1/modules/%s/%s/%s/versions",
		pkgAddr.Host.String(), pkgAddr.Namespace, pkgAddr.Name, pkgAddr.TargetSystem)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionUrl, nil)
	if err != nil {
		return ModulePackageVersionsResponse{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return ModulePackageVersionsResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ModulePackageVersionsResponse{}, fmt.Errorf("unexpected status code for versions endpoint: %d", resp.StatusCode)
	}

	var availableVersions moduleVersions
	if err := json.NewDecoder(resp.Body).Decode(&availableVersions); err != nil {
		return ModulePackageVersionsResponse{}, err
	}

	// TODO: check the length
	return availableVersions.Modules[0], nil
}

type moduleVersions struct {
	Modules []ModulePackageVersionsResponse `json:"modules"`
}

func (c *registryClient) ModulePackageSourceAddr(ctx context.Context, pkgAddr regaddr.ModulePackage, version versions.Version) (ModulePackageSourceAddrResponse, error) {

	hostname := pkgAddr.Host.String()
	url := fmt.Sprintf("https://%s/v1/modules/%s/%s/%s/%s/download", hostname, pkgAddr.Namespace, pkgAddr.Name, pkgAddr.TargetSystem, version.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ModulePackageSourceAddrResponse{}, err
	}

	req.Header.Set("X-Terraform-Version", version.String())
	resp, err := c.client.Do(req)
	if err != nil {
		return ModulePackageSourceAddrResponse{}, err
	}
	defer resp.Body.Close()

	var loc string

	// OpenTofu may return 200 with body
	switch resp.StatusCode {
	case http.StatusOK:
		// https://opentofu.org/docs/internals/module-registry-protocol/#sample-response-1
		var downloadResponse struct {
			Location string `json:"location"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&downloadResponse); err != nil {
			return ModulePackageSourceAddrResponse{}, fmt.Errorf("failed to decode download response: %w", err)
		}
		loc = downloadResponse.Location
	case http.StatusNoContent:
		loc = resp.Header.Get("X-Terraform-Get")
	default:
		return ModulePackageSourceAddrResponse{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	remoteSrc, err := sourceaddrs.ParseRemoteSource(loc)
	if err != nil {
		return ModulePackageSourceAddrResponse{}, err
	}

	return ModulePackageSourceAddrResponse{SourceAddr: remoteSrc}, nil
}
