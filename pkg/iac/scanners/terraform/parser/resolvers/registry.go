package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/log"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
	xsync "github.com/aquasecurity/trivy/pkg/x/sync"
)

type registryResolver struct {
	client           *http.Client
	modulesEndpoints xsync.Map[string, string]
}

var Registry = &registryResolver{
	// give it a maximum 5 seconds to resolve the module
	client: xhttp.Client(xhttp.WithTimeout(5 * time.Second)),
}

type moduleVersions struct {
	Modules []moduleProviderVersions `json:"modules"`
}

type moduleProviderVersions struct {
	Versions []moduleVersion `json:"versions"`
}

type moduleVersion struct {
	Version string `json:"version"`
}

const (
	registryHostname     = "registry.terraform.io"
	defaultModulesPath   = "/v1/modules/"
	serviceDiscoveryPath = "/.well-known/terraform.json"
)

var errDiscoveryUnreachable = errors.New("service discovery request failed")

// nolint
func (r *registryResolver) Resolve(ctx context.Context, target fs.FS, opt Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error) {

	client := r.client
	if opt.Client != nil {
		client = opt.Client
	}

	if !opt.AllowDownloads {
		return
	}

	inputVersion := opt.Version
	source, _ := splitPackageSubdirRaw(opt.OriginalSource)
	parts := strings.Split(source, "/")
	if len(parts) < 3 || len(parts) > 4 {
		return
	}

	hostname := registryHostname
	var token string
	if len(parts) == 4 {
		hostname = parts[0]
		parts = parts[1:]

		token, err = getPrivateRegistryTokenFromEnvVars(hostname)
		if err == nil {
			opt.Logger.Debug("Found a token for the registry", log.String("hostname", hostname))
		} else {
			opt.Logger.Error(
				"Failed to find a token for the registry",
				log.String("hostname", hostname), log.Err(err))
		}
	}

	moduleName := strings.Join(parts, "/")
	moduleUrl := r.modulesEndpoint(ctx, client, hostname, opt.Logger) + moduleName

	if opt.Version != "" {
		versionUrl := moduleUrl + "/versions"
		opt.Logger.Debug("Requesting module versions from registry using",
			log.String("url", versionUrl))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionUrl, nil)
		if err != nil {
			return nil, "", "", true, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", "", true, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, "", "", true, fmt.Errorf("unexpected status code for versions endpoint: %d", resp.StatusCode)
		}
		var availableVersions moduleVersions
		if err := json.NewDecoder(resp.Body).Decode(&availableVersions); err != nil {
			return nil, "", "", true, err
		}

		opt.Version, err = resolveVersion(inputVersion, availableVersions)
		if err != nil {
			return nil, "", "", true, err
		}
		opt.Logger.Debug("Found module version",
			log.String("version", opt.Version), log.String("constraint", inputVersion))
	}

	downloadUrl := moduleUrl + "/download"
	if opt.Version != "" {
		downloadUrl = moduleUrl + "/" + opt.Version + "/download"
	}

	opt.Logger.Debug("Requesting module source from registry", log.String("url", downloadUrl))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadUrl, nil)
	if err != nil {
		return nil, "", "", true, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if opt.Version != "" {
		req.Header.Set("X-Terraform-Version", opt.Version)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", true, err
	}
	defer func() { _ = resp.Body.Close() }()

	// OpenTofu may return 200 with body
	switch resp.StatusCode {
	case http.StatusOK:
		// https://opentofu.org/docs/internals/module-registry-protocol/#sample-response-1
		var downloadResponse struct {
			Location string `json:"location"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&downloadResponse); err != nil {
			return nil, "", "", true, fmt.Errorf("failed to decode download response: %w", err)
		}

		opt.Source = downloadResponse.Location
	case http.StatusNoContent:
		opt.Source = resp.Header.Get("X-Terraform-Get")
	default:
		return nil, "", "", true, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	if opt.Source == "" {
		return nil, "", "", true, fmt.Errorf("no source was found for the registry at %s", hostname)
	}

	opt.Source, err = resolveDownloadLocation(downloadUrl, opt.Source)
	if err != nil {
		return nil, "", "", true, err
	}

	opt.Logger.Debug("Module resolved via registry to new source",
		log.String("source", opt.Source), log.String("name", moduleName))

	filesystem, prefix, downloadPath, _, err = Remote.Resolve(ctx, target, opt)
	if err != nil {
		return nil, "", "", true, err
	}

	return filesystem, prefix, downloadPath, true, nil
}

// modulesEndpoint resolves the "modules.v1" base URL (trailing slash) of a registry host through
// https://developer.hashicorp.com/terraform/internals/remote-service-discovery, cached per host.
func (r *registryResolver) modulesEndpoint(ctx context.Context, client *http.Client, hostname string, logger *log.Logger) string {
	if cached, ok := r.modulesEndpoints.Load(hostname); ok {
		return cached
	}

	endpoint, err := discoverModulesEndpoint(ctx, client, hostname)
	if err != nil {
		endpoint = "https://" + hostname + defaultModulesPath
		logger.Debug("Remote service discovery failed, falling back to the default modules endpoint",
			log.String("hostname", hostname), log.String("url", endpoint), log.Err(err))
	} else {
		logger.Debug("Discovered module registry endpoint",
			log.String("hostname", hostname), log.String("url", endpoint))
	}

	// A host that could not be reached may still answer later; only a definitive answer is cached.
	if !errors.Is(err, errDiscoveryUnreachable) {
		r.modulesEndpoints.Store(hostname, endpoint)
	}
	return endpoint
}

func discoverModulesEndpoint(ctx context.Context, client *http.Client, hostname string) (string, error) {
	discoveryUrl := &url.URL{Scheme: "https", Host: hostname, Path: serviceDiscoveryPath}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryUrl.String(), http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errDiscoveryUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code for service discovery: %d", resp.StatusCode)
	}

	var services struct {
		ModulesV1 string `json:"modules.v1"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return "", fmt.Errorf("failed to decode service discovery document: %w", err)
	}
	if services.ModulesV1 == "" {
		return "", errors.New("service discovery document does not advertise modules.v1")
	}

	modulesUrl, err := discoveryUrl.Parse(services.ModulesV1)
	if err != nil {
		return "", fmt.Errorf("invalid modules.v1 endpoint %q: %w", services.ModulesV1, err)
	}
	// The registry bearer token is sent to this endpoint, so a plaintext scheme would leak it.
	if modulesUrl.Scheme != "https" {
		return "", fmt.Errorf("modules.v1 endpoint %q must use https", services.ModulesV1)
	}
	endpoint := modulesUrl.String()
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	return endpoint, nil
}

// resolveDownloadLocation turns a relative download location ("/", "./" or "../" prefixed) into an
// absolute URL against the download endpoint, as the module registry protocol allows. Anything else,
// including go-getter forced sources such as "git::https://...", is returned unchanged.
// https://developer.hashicorp.com/terraform/internals/module-registry-protocol#download-source-code-for-a-specific-module-version
func resolveDownloadLocation(downloadUrl, location string) (string, error) {
	if !strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "./") && !strings.HasPrefix(location, "../") {
		return location, nil
	}
	base, err := url.Parse(downloadUrl)
	if err != nil {
		return "", fmt.Errorf("invalid download url %q: %w", downloadUrl, err)
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid relative download location %q: %w", location, err)
	}
	return base.ResolveReference(ref).String(), nil
}

func getPrivateRegistryTokenFromEnvVars(hostname string) (string, error) {
	token := ""
	asciiHostname, err := idna.ToASCII(hostname)
	if err != nil {
		return "", fmt.Errorf("could not convert hostname %s to a punycode encoded ASCII string so cannot find token for this registry", hostname)
	}

	envVar := fmt.Sprintf("TF_TOKEN_%s", strings.ReplaceAll(asciiHostname, ".", "_"))
	token = os.Getenv(envVar)

	// Dashes in the hostname can optionally be converted to double underscores
	if token == "" {
		envVar = strings.ReplaceAll(envVar, "-", "__")
		token = os.Getenv(envVar)
	}

	if token == "" {
		return "", fmt.Errorf("no token was found for the registry at %s", hostname)
	}
	return token, nil
}

func resolveVersion(input string, versions moduleVersions) (string, error) {
	if len(versions.Modules) != 1 {
		return "", fmt.Errorf("1 module expected, found %d", len(versions.Modules))
	}
	if len(versions.Modules[0].Versions) == 0 {
		return "", errors.New("no available versions for module")
	}

	constraints, err := version.NewConstraints(input)
	if err != nil {
		return "", err
	}
	var realVersions version.Collection
	for _, rawVersion := range versions.Modules[0].Versions {
		realVersion, err := version.Parse(rawVersion.Version)
		if err != nil {
			continue
		}
		realVersions = append(realVersions, realVersion)
	}
	sort.Sort(sort.Reverse(realVersions))
	for _, realVersion := range realVersions {
		if constraints.Check(realVersion) {
			return realVersion.String(), nil
		}
	}
	return "", fmt.Errorf("no available versions for module constraint '%s'", input)
}
