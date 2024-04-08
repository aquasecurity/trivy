package parallel

import (
	"context"
	"io/fs"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const defaultParallel = 5

type onFile[T any] func(string, fs.FileInfo, xio.ReadSeekerAt) (T, error)
type onWalkResult[T any] func(T) error

func WalkDir[T any](ctx context.Context, fsys fs.FS, root string, parallel int,
	onFile onFile[T], onResult onWalkResult[T]) error {

	g, ctx := errgroup.WithContext(ctx)
	paths := make(chan string)

	g.Go(func() error {
		defer close(paths)
		err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			} else if !d.Type().IsRegular() {
				return nil
			}

			// check if file is empty
			info, err := d.Info()
			if err != nil {
				return err
			} else if info.Size() == 0 {
				log.Logger.Debugf("%s is empty, skip this file", path)
				return nil
			}

			select {
			case paths <- path:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf("walk error: %w", err)
		}
		return nil
	})

	// Start a fixed number of goroutines to read and digest files.
	c := make(chan T)
	if parallel == 0 {
		parallel = defaultParallel
	}
	for i := 0; i < parallel; i++ {
		g.Go(func() error {
			for path := range paths {
				if err := walk(ctx, fsys, path, c, onFile); err != nil {
					return err
				}
			}
			return nil
		})
	}
	go func() {
		_ = g.Wait()
		close(c)
	}()

	for res := range c {
		if err := onResult(res); err != nil {
			return err
		}
	}
	// Check whether any of the goroutines failed. Since g is accumulating the
	// errors, we don't need to send them (or check for them) in the individual
	// results sent on the channel.
	if err := g.Wait(); err != nil {
		return err
	}
	return nil
}

func walk[T any](ctx context.Context, fsys fs.FS, path string, c chan T, onFile onFile[T]) error {
	f, err := fsys.Open(path)
	if err != nil {
		return xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return xerrors.Errorf("stat error: %w", err)
	}

	rsa, ok := f.(xio.ReadSeekerAt)
	if !ok {
		return xerrors.New("type assertion failed")
	}
	res, err := onFile(path, info, rsa)
	if err != nil {
		log.Logger.Debugw("Walk error", zap.String("file_path", path), zap.Error(err))
		return nil
	}

	select {
	case c <- res:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
