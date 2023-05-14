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

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/reference/docker"
	refdocker "github.com/containerd/containerd/reference/docker"
	api "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
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

func imageWriter(client *containerd.Client, img containerd.Image) imageSave {
	return func(ctx context.Context, ref []string) (io.ReadCloser, error) {
		if len(ref) < 1 {
			return nil, xerrors.New("no image reference")
		}
		imgOpts := archive.WithImage(client.ImageService(), ref[0])
		manifestOpts := archive.WithManifest(img.Target())
		platOpts := archive.WithPlatform(platforms.DefaultStrict())
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(archive.Export(ctx, client.ContentStore(), pw, imgOpts, manifestOpts, platOpts))
		}()
		return pr, nil
	}
}

// ContainerdImage implements v1.Image
func ContainerdImage(ctx context.Context, imageName string) (Image, func(), error) {
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

	client, err := containerd.New(addr)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a containerd client: %w", err)
	}

	namespace := os.Getenv("CONTAINERD_NAMESPACE")
	if namespace == "" {
		namespace = defaultContainerdNamespace
	}

	ctx = namespaces.WithNamespace(ctx, namespace)

	imgs, err := client.ListImages(ctx, searchFilters...)
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
		_ = client.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	insp, history, ref, err := inspect(ctx, img, ref)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("inspect error: %w", err)
	}

	return &image{
		opener:  imageOpener(ctx, ref.String(), f, imageWriter(client, img)),
		inspect: insp,
		history: history,
	}, cleanup, nil
}

func parseReference(imageName string) (refdocker.Reference, []string, error) {
	ref, err := refdocker.ParseAnyReference(imageName)
	if err != nil {
		return nil, nil, xerrors.Errorf("parse error: %w", err)
	}

	d, isDigested := ref.(refdocker.Digested)
	n, isNamed := ref.(refdocker.Named)
	nt, isNamedAndTagged := ref.(refdocker.NamedTagged)

	// a name plus a digest
	// example: name@sha256:41adb3ef...
	if isDigested && isNamed {
		digest := d.Digest()
		// for the filters, each slice entry is logically or'd. each
		// comma-separated filter is logically anded
		return ref, []string{
			fmt.Sprintf(`name~="^%s(:|@).*",target.digest=="%s"`, n.Name(), digest),
			fmt.Sprintf(`name~="^%s(:|@).*",target.digest=="%s"`, refdocker.FamiliarName(n), digest),
		}, nil
	}

	// digested, but not named. i.e. a plain digest
	// example: sha256:41adb3ef...
	if isDigested {
		return ref, []string{fmt.Sprintf(`target.digest=="%s"`, d.Digest())}, nil
	}

	// a name plus a tag
	// example: name:tag
	if isNamedAndTagged {
		tag := nt.Tag()
		return familiarNamed(imageName), []string{
			fmt.Sprintf(`name=="%s:%s"`, nt.Name(), tag),
			fmt.Sprintf(`name=="%s:%s"`, refdocker.FamiliarName(nt), tag),
		}, nil
	}

	return nil, nil, xerrors.Errorf("failed to parse image reference: %s", imageName)
}

// readImageConfig reads the config spec (`application/vnd.oci.image.config.v1+json`) for img.platform from content store.
// ported from https://github.com/containerd/nerdctl/blob/7dfbaa2122628921febeb097e7a8a86074dc931d/pkg/imgutil/imgutil.go#L377-L393
func readImageConfig(ctx context.Context, img containerd.Image) (ocispec.Image, ocispec.Descriptor, error) {
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
func inspect(ctx context.Context, img containerd.Image, ref docker.Reference) (api.ImageInspect, []v1.History, refdocker.Reference, error) {
	if _, ok := ref.(refdocker.Digested); ok {
		ref = familiarNamed(img.Name())
	}

	var tag string
	if tagged, ok := ref.(refdocker.Tagged); ok {
		tag = tagged.Tag()
	}

	var repository string
	if n, isNamed := ref.(docker.Named); isNamed {
		repository = refdocker.FamiliarName(n)
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

	return api.ImageInspect{
		ID:          imgConfigDesc.Digest.String(),
		RepoTags:    []string{fmt.Sprintf("%s:%s", repository, tag)},
		RepoDigests: []string{fmt.Sprintf("%s@%s", repository, img.Target().Digest)},
		Comment:     lastHistory.Comment,
		Created:     lastHistory.Created.Format(time.RFC3339Nano),
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
