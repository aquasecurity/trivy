package image

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/token"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func tryRemote(ctx context.Context, imageName string, ref name.Reference, option types.DockerOption) (types.Image, error) {
	var remoteOpts []remote.Option
	d := &net.Dialer{
		Timeout: 10 * time.Minute,
	}
	t := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
		DialContext:       d.DialContext,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: option.InsecureSkipTLSVerify},
	}
	remoteOpts = append(remoteOpts, remote.WithTransport(t))

	domain := ref.Context().RegistryStr()
	auth := token.GetToken(ctx, domain, option)

	if auth.Username != "" && auth.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&auth))
	} else if option.RegistryToken != "" {
		bearer := authn.Bearer{Token: option.RegistryToken}
		remoteOpts = append(remoteOpts, remote.WithAuth(&bearer))
	} else {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	if option.Platform != "" {
		s, err := parsePlatform(ref, option.Platform, remoteOpts, option.ForcePlatform)
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
		return nil, err
	}

	img, err := desc.Image()
	if err != nil {
		return nil, err
	}

	// Return v1.Image if the image is found in Docker Registry
	return remoteImage{
		name:       imageName,
		Image:      img,
		ref:        implicitReference{ref: ref},
		descriptor: desc,
	}, nil

}

func parsePlatform(ref name.Reference, p string, options []remote.Option, forcePlatform bool) (*v1.Platform, error) {
	// OS wildcard, implicitly pick up the first os found in the image list.
	// e.g. */amd64
	d, err := remote.Get(ref, options...)
	if err != nil {
		return nil, xerrors.Errorf("image get error: %w", err)
	}
	platform, err := v1.ParsePlatform(p)
	if err != nil {
		return nil, xerrors.Errorf("platform parse error: %w", err)
	}
	switch d.MediaType {
	case v1types.OCIManifestSchema1, v1types.DockerManifestSchema2:
		// We want an index but the registry has an image, not multi-arch. We just ignore "--platform".
		if !forcePlatform {
			log.Logger.Debug("Ignore --platform as the image is not multi-arch")
			return nil, nil
		}
		// Image is not a multi-arch image, but we can extract the OS from the image's config file.
		img, err := d.Image()
		if err != nil {
			return nil, xerrors.Errorf("remote index error: %w", err)
		}
		cfg, err := img.ConfigFile()
		if err != nil {
			return nil, xerrors.Errorf("remote config file error: %w", err)
		}
		// set image OS if platform's is "*"
		platform, err = platformCompare(platform, &v1.Platform{
			Architecture: cfg.Architecture,
			OS:           cfg.OS,
		})
		if err != nil {
			return nil, xerrors.Errorf("image does not support the requested platform: %w", err)
		}

	case v1types.OCIImageIndex, v1types.DockerManifestList:
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
		if !forcePlatform {
			if len(m.Manifests) > 0 && m.Manifests[0].Platform != nil {
				// Replace with the detected OS
				// e.g. */amd64 => linux/amd64
				platform.OS = m.Manifests[0].Platform.OS
				platform.Architecture = m.Manifests[0].Platform.Architecture
			}
		} else {
			var foundPlatform bool
			for _, manifest := range m.Manifests {
				// set image OS only if the arch matches
				platformNew, err := platformCompare(platform, manifest.Platform)
				if err != nil && platformNew == nil {
					continue
				}
				foundPlatform = true
				break
			}
			if !foundPlatform {
				return nil, xerrors.Errorf("image does not support the requested platform: %w", err)
			}
		}
	}
	return platform, nil
}

func platformCompare(sourcePlatform *v1.Platform, targetPlatform *v1.Platform) (*v1.Platform, error) {
	if sourcePlatform.Architecture == targetPlatform.Architecture {
		if sourcePlatform.OS != "*" && targetPlatform.OS != sourcePlatform.OS {
			return nil, xerrors.Errorf("image does not support the requested platform")
		} else if sourcePlatform.OS == "*" && targetPlatform.OS != "" {
			sourcePlatform.OS = targetPlatform.OS
		}
	} else {
		return nil, xerrors.Errorf("image does not support the requested platform")
	}
	return sourcePlatform, nil
}

type remoteImage struct {
	name       string
	ref        implicitReference
	descriptor *remote.Descriptor
	v1.Image
}

func (img remoteImage) Name() string {
	return img.name
}

func (img remoteImage) ID() (string, error) {
	return ID(img)
}

func (img remoteImage) RepoTags() []string {
	tag := img.ref.TagName()
	if tag == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("%s:%s", img.ref.RepositoryName(), tag)}
}

func (img remoteImage) RepoDigests() []string {
	repoDigest := fmt.Sprintf("%s@%s", img.ref.RepositoryName(), img.descriptor.Digest.String())
	return []string{repoDigest}
}

type implicitReference struct {
	ref name.Reference
}

func (r implicitReference) TagName() string {
	if t, ok := r.ref.(name.Tag); ok {
		return t.TagStr()
	}
	return ""
}

func (r implicitReference) RepositoryName() string {
	ctx := r.ref.Context()
	reg := ctx.RegistryStr()
	repo := ctx.RepositoryStr()

	// Default registry
	if reg != name.DefaultRegistry {
		return fmt.Sprintf("%s/%s", reg, repo)
	}

	// Trim default namespace
	// See https://docs.docker.com/docker-hub/official_repos
	return strings.TrimPrefix(repo, "library/")
}
