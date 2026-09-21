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
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/log"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
)

type registryResolver struct {
	client *http.Client
	// modulesEndpoints caches the discovered "modules.v1" base URL per registry hostname.
	modulesEndpoints sync.Map
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
	registryHostname = "registry.terraform.io"
	// defaultModulesPath is the module registry base path used when remote service discovery
	// is unavailable or does not advertise "modules.v1".
	defaultModulesPath = "/v1/modules/"
	// serviceDiscoveryPath is the well-known document a Terraform host serves to advertise
	// where its services live: https://developer.hashicorp.com/terraform/internals/remote-service-discovery
	serviceDiscoveryPath = "/.well-known/terraform.json"
)

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
	modulesEndpoint := r.modulesEndpoint(ctx, client, hostname, opt.Logger)

	if opt.Version != "" {
		versionUrl := modulesEndpoint + moduleName + "/versions"
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

	var downloadUrl string
	if opt.Version == "" {
		downloadUrl = modulesEndpoint + moduleName + "/download"
	} else {
		downloadUrl = modulesEndpoint + moduleName + "/" + opt.Version + "/download"
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

	opt.Logger.Debug("Module resolved via registry to new source",
		log.String("source", opt.Source), log.String("name", moduleName))

	filesystem, prefix, downloadPath, _, err = Remote.Resolve(ctx, target, opt)
	if err != nil {
		return nil, "", "", true, err
	}

	return filesystem, prefix, downloadPath, true, nil
}

// modulesEndpoint returns the module registry base URL for a hostname, with a trailing slash.
// It follows Terraform's remote service discovery: the host's /.well-known/terraform.json
// document names the "modules.v1" endpoint, which may live under any path (Terraform Cloud
// serves it at /api/registry/v1/modules/). Hosts without discovery fall back to /v1/modules/.
func (r *registryResolver) modulesEndpoint(ctx context.Context, client *http.Client, hostname string, logger *log.Logger) string {
	if cached, ok := r.modulesEndpoints.Load(hostname); ok {
		return cached.(string)
	}

	fallback := "https://" + hostname + defaultModulesPath
	endpoint, err := discoverModulesEndpoint(ctx, client, hostname)
	if err != nil {
		logger.Debug("Remote service discovery failed, falling back to the default modules endpoint",
			log.String("hostname", hostname), log.String("url", fallback), log.Err(err))
		endpoint = fallback
	} else {
		logger.Debug("Discovered module registry endpoint",
			log.String("hostname", hostname), log.String("url", endpoint))
	}

	r.modulesEndpoints.Store(hostname, endpoint)
	return endpoint
}

func discoverModulesEndpoint(ctx context.Context, client *http.Client, hostname string) (string, error) {
	discoveryUrl := "https://" + hostname + serviceDiscoveryPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryUrl, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
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

	// The value is either an absolute URL or a path relative to the discovery document.
	base, err := url.Parse(discoveryUrl)
	if err != nil {
		return "", err
	}
	modulesUrl, err := base.Parse(services.ModulesV1)
	if err != nil {
		return "", fmt.Errorf("invalid modules.v1 endpoint %q: %w", services.ModulesV1, err)
	}
	if modulesUrl.Scheme != "https" {
		return "", fmt.Errorf("modules.v1 endpoint %q must use https", services.ModulesV1)
	}
	endpoint := modulesUrl.String()
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	return endpoint, nil
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
