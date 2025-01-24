package image

import (
	"context"
	"io"

	"github.com/cheggaaa/pb/v3"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
)

// progressLayer wraps a types.Image to add progress bar functionality
type progressImage struct {
	types.Image
	pool *pb.Pool
}

func newProgressImage(img types.Image, pool *pb.Pool) types.Image {
	return &progressImage{
		Image: img,
		pool:  pool,
	}
}

func (i *progressImage) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	layer, err := i.Image.LayerByDiffID(h)
	if err != nil {
		return nil, xerrors.Errorf("failed to get image layer by diff id %s: %w", h.String(), err)
	}

	size, err := layer.Size()
	if err != nil {
		return nil, err
	}

	bar := pb.New64(size).SetTemplate(pb.Full).
		Set("prefix", shortenHash(h.Hex, 12))

	pl, err := newProgressLayer(layer, bar)
	if err != nil {
		return nil, xerrors.Errorf("failed to create progress layer: %w", err)
	}
	i.pool.Add(bar)

	return pl, nil
}

func shortenHash(hash string, length int) string {
	if len(hash) > length {
		return hash[:length]
	}
	return hash
}

// progressLayer wraps a v1.Layer to add progress bar functionality
type progressLayer struct {
	v1.Layer
	bar *pb.ProgressBar
}

func newProgressLayer(layer v1.Layer, bar *pb.ProgressBar) (v1.Layer, error) {
	return partial.CompressedToLayer(&progressLayer{
		Layer: layer,
		bar:   bar,
	})
}

func (l *progressLayer) Compressed() (io.ReadCloser, error) {
	rc, err := l.Layer.Compressed()
	if err != nil {
		return nil, err
	}
	return l.bar.NewProxyReader(rc), nil
}

type imageWalker struct {
	numWorkers int
	progress   bool
	image      types.Image
}

func newImageWalker(numWorkers int, progress bool, image types.Image) *imageWalker {
	return &imageWalker{
		numWorkers: numWorkers,
		progress:   progress,
		image:      image,
	}
}

// walk processes container image layers concurrently using the provided callbacks, with optional progress display if enabled.
func (w *imageWalker) walk(ctx context.Context, diffIDs []string, onLayer func(l v1.Layer, diffID string) (any, error), onResult func(any) error) error {
	image := w.image

	if w.progress {
		pool := pb.NewPool()
		image = newProgressImage(image, pool)
		// This is a small hack. The pool works as long as there is at least one unfinished bar,
		// so we use a dummy empty bar so that the pool can work before adding a bar.
		dummyBar := pb.New(len(diffIDs)).SetTemplateString("")
		pool.Add(dummyBar)
		defer dummyBar.Finish()
		if err := pool.Start(); err != nil {
			log.Error("Failed to start progress bar pool", log.Err(err))
		} else {
			defer pool.Stop()
		}
	}

	p := parallel.NewPipeline(w.numWorkers, false, diffIDs, func(ctx context.Context, diffID string) (ret any, err error) {
		h, err := v1.NewHash(diffID)
		if err != nil {
			return nil, xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
		}
		layer, err := image.LayerByDiffID(h)
		if err != nil {
			return nil, xerrors.Errorf("failed to get image layer by diff id %s: %w", h.String(), err)
		}
		res, err := onLayer(layer, diffID)
		if err != nil {
			return nil, err
		}
		return res, nil
	}, onResult)

	if err := p.Do(ctx); err != nil {
		return err
	}
	return nil
}
