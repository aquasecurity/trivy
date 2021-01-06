package image

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/aquasecurity/fanal/image/token"
	"github.com/aquasecurity/fanal/types"
)

func tryRemote(ctx context.Context, ref name.Reference, option types.DockerOption) (v1.Image, extender, error) {
	var remoteOpts []remote.Option
	if option.InsecureSkipTLSVerify {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(t))
	}

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

	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return nil, nil, err
	}

	img, err := desc.Image()
	if err != nil {
		return nil, nil, err
	}

	// Return v1.Image if the image is found in Docker Registry
	return img, remoteExtender{
		ref:        implicitReference{ref: ref},
		descriptor: desc,
	}, nil
}

type remoteExtender struct {
	ref        implicitReference
	descriptor *remote.Descriptor
}

func (e remoteExtender) RepoTags() []string {
	tag := e.ref.TagName()
	if tag == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("%s:%s", e.ref.RepositoryName(), tag)}
}

func (e remoteExtender) RepoDigests() []string {
	repoDigest := fmt.Sprintf("%s@%s", e.ref.RepositoryName(), e.descriptor.Digest.String())
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
