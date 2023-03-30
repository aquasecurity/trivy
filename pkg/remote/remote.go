package remote

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Descriptor = remote.Descriptor

// Get is a wrapper of google/go-containerregistry/pkg/v1/remote.Get
// so that it can try multiple authentication methods.
func Get(ctx context.Context, ref name.Reference, option types.RemoteOptions) (*Descriptor, error) {
	transport := httpTransport(option.Insecure)

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, ref, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(transport),
			authOpt,
		}

		if option.Platform != "" {
			s, err := parsePlatform(ref, option.Platform, remoteOpts)
			if err != nil {
				return nil, xerrors.Errorf("platform error: %w", err)
			}
			// Don't pass platform when the specified image is single-arch.
			if s != nil {
				remoteOpts = append(remoteOpts, remote.WithPlatform(*s))
			}
		}

		desc, err := remote.Get(ref, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		return desc, nil
	}

	// No authentication succeeded
	return nil, errs
}

// Image is a wrapper of google/go-containerregistry/pkg/v1/remote.Image
// so that it can try multiple authentication methods.
func Image(ctx context.Context, ref name.Reference, option types.RemoteOptions) (v1.Image, error) {
	transport := httpTransport(option.Insecure)

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, ref, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(transport),
			authOpt,
		}
		index, err := remote.Image(ref, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		return index, nil
	}

	// No authentication succeeded
	return nil, errs
}

// Referrers is a wrapper of google/go-containerregistry/pkg/v1/remote.Referrers
// so that it can try multiple authentication methods.
func Referrers(ctx context.Context, d name.Digest, option types.RemoteOptions) (*v1.IndexManifest, error) {
	transport := httpTransport(option.Insecure)

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, d, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(transport),
			authOpt,
		}
		index, err := remote.Referrers(d, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		return index, nil
	}

	// No authentication succeeded
	return nil, errs
}

func httpTransport(insecure bool) *http.Transport {
	d := &net.Dialer{
		Timeout: 10 * time.Minute,
	}
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
		DialContext:       d.DialContext,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
	}
}

func authOptions(ctx context.Context, ref name.Reference, option types.RemoteOptions) []remote.Option {
	var opts []remote.Option
	for _, cred := range option.Credentials {
		opts = append(opts, remote.WithAuth(&authn.Basic{
			Username: cred.Username,
			Password: cred.Password,
		}))
	}

	domain := ref.Context().RegistryStr()
	token := registry.GetToken(ctx, domain, option)
	if !lo.IsEmpty(token) {
		opts = append(opts, remote.WithAuth(&token))
	}

	switch {
	case option.RegistryToken != "":
		bearer := authn.Bearer{Token: option.RegistryToken}
		return []remote.Option{remote.WithAuth(&bearer)}
	default:
		// Use the keychain anyway at the end
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		return opts
	}
}

func parsePlatform(ref name.Reference, p string, options []remote.Option) (*v1.Platform, error) {
	// OS wildcard, implicitly pick up the first os found in the image list.
	// e.g. */amd64
	if strings.HasPrefix(p, "*/") {
		d, err := remote.Get(ref, options...)
		if err != nil {
			return nil, xerrors.Errorf("image get error: %w", err)
		}
		switch d.MediaType {
		case v1types.OCIManifestSchema1, v1types.DockerManifestSchema2:
			// We want an index but the registry has an image, not multi-arch. We just ignore "--platform".
			log.Logger.Debug("Ignore --platform as the image is not multi-arch")
			return nil, nil
		case v1types.OCIImageIndex, v1types.DockerManifestList:
			// These are expected.
		}

		index, err := d.ImageIndex()
		if err != nil {
			return nil, xerrors.Errorf("image index error: %w", err)
		}

		m, err := index.IndexManifest()
		if err != nil {
			return nil, xerrors.Errorf("remote index manifest error: %w", err)
		}
		if len(m.Manifests) == 0 {
			log.Logger.Debug("Ignore --platform as the image is not multi-arch")
			return nil, nil
		}
		if m.Manifests[0].Platform != nil {
			// Replace with the detected OS
			// e.g. */amd64 => linux/amd64
			p = m.Manifests[0].Platform.OS + strings.TrimPrefix(p, "*")
		}
	}
	platform, err := v1.ParsePlatform(p)
	if err != nil {
		return nil, xerrors.Errorf("platform parse error: %w", err)
	}
	return platform, nil
}
