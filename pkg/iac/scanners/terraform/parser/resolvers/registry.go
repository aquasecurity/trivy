package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/log"
)

type registryResolver struct {
	client *http.Client
}

var Registry = &registryResolver{
	client: &http.Client{
		// give it a maximum 5 seconds to resolve the module
		Timeout: time.Second * 5,
	},
}

type moduleVersions struct {
	Modules []struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	} `json:"modules"`
}

const registryHostname = "registry.terraform.io"

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

	if opt.Version != "" {
		versionUrl := fmt.Sprintf("https://%s/v1/modules/%s/versions", hostname, moduleName)
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

	var url string
	if opt.Version == "" {
		url = fmt.Sprintf("https://%s/v1/modules/%s/download", hostname, moduleName)
	} else {
		url = fmt.Sprintf("https://%s/v1/modules/%s/%s/download", hostname, moduleName, opt.Version)
	}

	opt.Logger.Debug("Requesting module source from registry", log.String("url", url))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
