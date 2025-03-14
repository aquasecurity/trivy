package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	api "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const (
	defaultContainerdSocket    = "/run/containerd/containerd.sock"
	defaultContainerdNamespace = "default"
)

type familiarNamed string

func (n familiarNamed) Name() string {
	return strings.Split(string(n), ":")[0]
}

func (n familiarNamed) Tag() string {
	s := strings.Split(string(n), ":")
	if len(s) < 2 {
		return ""
	}

	return s[1]
}

func (n familiarNamed) String() string {
	return string(n)
}

func imageWriter(c *client.Client, img client.Image, platform types.Platform) imageSave {
	return func(ctx context.Context, ref []string) (io.ReadCloser, error) {
		if len(ref) < 1 {
			return nil, xerrors.New("no image reference")
		}
		imgOpts := archive.WithImage(c.ImageService(), ref[0])
		manifestOpts := archive.WithManifest(img.Target())

		var platformMatchComparer platforms.MatchComparer
		if platform.Platform == nil {
			platformMatchComparer = platforms.DefaultStrict()
		} else {
			platformMatchComparer = img.Platform()
		}
		platOpts := archive.WithPlatform(platformMatchComparer)
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(archive.Export(ctx, c.ContentStore(), pw, imgOpts, manifestOpts, platOpts))
		}()
		return pr, nil
	}
}

// ContainerdImage implements v1.Image
func ContainerdImage(ctx context.Context, imageName string, opts types.ImageOptions) (Image, func(), error) {
	cleanup := func() {}

	addr := os.Getenv("CONTAINERD_ADDRESS")
	if addr == "" {
		// TODO: support rootless
		addr = defaultContainerdSocket
	}

	if _, err := os.Stat(addr); errors.Is(err, os.ErrNotExist) {
		return nil, cleanup, xerrors.Errorf("containerd socket not found: %s", addr)
	}

	ref, searchFilters, err := parseReference(imageName)
	if err != nil {
		return nil, cleanup, err
	}

	var options []client.Opt
	if opts.RegistryOptions.Platform.Platform != nil {
		ociPlatform, err := platforms.Parse(opts.RegistryOptions.Platform.String())
		if err != nil {
			return nil, cleanup, err
		}

		options = append(options, client.WithDefaultPlatform(platforms.OnlyStrict(ociPlatform)))
	}

	c, err := client.New(addr, options...)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a containerd client: %w", err)
	}

	namespace := os.Getenv("CONTAINERD_NAMESPACE")
	if namespace == "" {
		namespace = defaultContainerdNamespace
	}

	ctx = namespaces.WithNamespace(ctx, namespace)

	imgs, err := c.ListImages(ctx, searchFilters...)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to list images from containerd client: %w", err)
	}

	if len(imgs) < 1 {
		return nil, cleanup, xerrors.Errorf("image not found in containerd store: %s", imageName)
	}

	img := imgs[0]

	f, err := os.CreateTemp("", "fanal-containerd-*")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = c.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	insp, history, ref, err := inspect(ctx, img, ref)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("inspect error: %w", err)
	}

	return &image{
		opener:  imageOpener(ctx, ref.String(), f, imageWriter(c, img, opts.RegistryOptions.Platform)),
		inspect: insp,
		history: history,
	}, cleanup, nil
}

func parseReference(imageName string) (reference.Reference, []string, error) {
	ref, err := reference.ParseAnyReference(imageName)
	if err != nil {
		return nil, nil, xerrors.Errorf("parse error: %w", err)
	}

	d, isDigested := ref.(reference.Digested)
	n, isNamed := ref.(reference.Named)
	nt, isNamedAndTagged := ref.(reference.NamedTagged)

	// a name plus a digest
	// example: name@sha256:41adb3ef...
	if isDigested && isNamed {
		dgst := d.Digest()
		// for the filters, each slice entry is logically or'd. each
		// comma-separated filter is logically anded
		return ref, []string{
			fmt.Sprintf(`name~="^%s(:|@).*",target.digest==%q`, n.Name(), dgst),
			fmt.Sprintf(`name~="^%s(:|@).*",target.digest==%q`, reference.FamiliarName(n), dgst),
		}, nil
	}

	// digested, but not named. i.e. a plain digest
	// example: sha256:41adb3ef...
	if isDigested {
		return ref, []string{fmt.Sprintf(`target.digest==%q`, d.Digest())}, nil
	}

	// a name plus a tag
	// example: name:tag
	if isNamedAndTagged {
		tag := nt.Tag()
		return familiarNamed(imageName), []string{
			fmt.Sprintf(`name=="%s:%s"`, nt.Name(), tag),
			fmt.Sprintf(`name=="%s:%s"`, reference.FamiliarName(nt), tag),
		}, nil
	}

	return nil, nil, xerrors.Errorf("failed to parse image reference: %s", imageName)
}

// readImageConfig reads the config spec (`application/vnd.oci.image.config.v1+json`) for img.platform from content store.
// ported from https://github.com/containerd/nerdctl/blob/7dfbaa2122628921febeb097e7a8a86074dc931d/pkg/imgutil/imgutil.go#L377-L393
func readImageConfig(ctx context.Context, img client.Image) (ocispec.Image, ocispec.Descriptor, error) {
	var config ocispec.Image

	configDesc, err := img.Config(ctx) // aware of img.platform
	if err != nil {
		return config, configDesc, err
	}
	p, err := content.ReadBlob(ctx, img.ContentStore(), configDesc)
	if err != nil {
		return config, configDesc, err
	}
	if err = json.Unmarshal(p, &config); err != nil {
		return config, configDesc, err
	}
	return config, configDesc, nil
}

// ported from https://github.com/containerd/nerdctl/blob/d110fea18018f13c3f798fa6565e482f3ff03591/pkg/inspecttypes/dockercompat/dockercompat.go#L279-L321
func inspect(ctx context.Context, img client.Image, ref reference.Reference) (api.ImageInspect, []v1.History, reference.Reference, error) {
	if _, ok := ref.(reference.Digested); ok {
		ref = familiarNamed(img.Name())
	}

	var tag string
	if tagged, ok := ref.(reference.Tagged); ok {
		tag = tagged.Tag()
	}

	var repository string
	if n, isNamed := ref.(reference.Named); isNamed {
		repository = reference.FamiliarName(n)
	}

	imgConfig, imgConfigDesc, err := readImageConfig(ctx, img)
	if err != nil {
		return api.ImageInspect{}, nil, nil, err
	}

	var lastHistory ocispec.History
	if len(imgConfig.History) > 0 {
		lastHistory = imgConfig.History[len(imgConfig.History)-1]
	}

	var history []v1.History
	for _, h := range imgConfig.History {
		history = append(history, v1.History{
			Author:     h.Author,
			Created:    v1.Time{Time: *h.Created},
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			EmptyLayer: h.EmptyLayer,
		})
	}

	portSet := make(nat.PortSet)
	for k := range imgConfig.Config.ExposedPorts {
		portSet[nat.Port(k)] = struct{}{}
	}

	created := ""
	if lastHistory.Created != nil {
		created = lastHistory.Created.Format(time.RFC3339Nano)
	}

	return api.ImageInspect{
		ID:          imgConfigDesc.Digest.String(),
		RepoTags:    []string{fmt.Sprintf("%s:%s", repository, tag)},
		RepoDigests: []string{fmt.Sprintf("%s@%s", repository, img.Target().Digest)},
		Comment:     lastHistory.Comment,
		Created:     created,
		Author:      lastHistory.Author,
		Config: &container.Config{
			User:         imgConfig.Config.User,
			ExposedPorts: portSet,
			Env:          imgConfig.Config.Env,
			Cmd:          imgConfig.Config.Cmd,
			Volumes:      imgConfig.Config.Volumes,
			WorkingDir:   imgConfig.Config.WorkingDir,
			Entrypoint:   imgConfig.Config.Entrypoint,
			Labels:       imgConfig.Config.Labels,
		},
		Architecture: imgConfig.Architecture,
		Os:           imgConfig.OS,
		RootFS: api.RootFS{
			Type: imgConfig.RootFS.Type,
			Layers: lo.Map(imgConfig.RootFS.DiffIDs, func(d digest.Digest, _ int) string {
				return d.String()
			}),
		},
	}, history, ref, nil
}
