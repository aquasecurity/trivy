package walker

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

// Walk wraps WalkWithContext using the background context.
func Walk(root string, walkFn func(pathname string, fi os.FileInfo) error, opts ...Option) error {
	return WalkWithContext(context.Background(), root, walkFn, opts...)
}

// WalkWithContext walks the file tree rooted at root, calling walkFn for each
// file or directory in the tree, including root.
//
// If fastWalk returns filepath.SkipDir, the directory is skipped.
//
// Multiple goroutines stat the filesystem concurrently. The provided
// walkFn must be safe for concurrent use.
func WalkWithContext(ctx context.Context, root string, walkFn func(pathname string, fi os.FileInfo) error, opts ...Option) error {
	wg, ctx := errgroup.WithContext(ctx)

	fi, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if err = walkFn(root, fi); err == filepath.SkipDir {
		return nil
	}
	if err != nil || !fi.IsDir() {
		return err
	}

	w := walker{
		counter: 1,
		limit:   runtime.NumCPU(),
		ctx:     ctx,
		wg:      wg,
		fn:      walkFn,
	}
	if w.limit < 4 {
		w.limit = 4
	}

	for _, o := range opts {
		err := o(&w.options)
		if err != nil {
			return err
		}
	}

	w.wg.Go(func() error {
		return w.gowalk(root)
	})

	return w.wg.Wait()
}

type walker struct {
	counter uint32
	limit   int
	ctx     context.Context
	wg      *errgroup.Group
	fn      func(pathname string, fi os.FileInfo) error
	options walkerOptions
}

func (w *walker) walk(dirname string, fi os.FileInfo) error {
	pathname := dirname + string(filepath.Separator) + fi.Name()

	err := w.fn(pathname, fi)
	if err == filepath.SkipDir {
		return nil
	}
	if err != nil {
		return err
	}

	// don't follow symbolic links
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	if !fi.IsDir() {
		return nil
	}

	if err = w.ctx.Err(); err != nil {
		return err
	}

	current := atomic.LoadUint32(&w.counter)

	// if we haven't reached our goroutine limit, spawn a new one
	if current < uint32(w.limit) {
		if atomic.CompareAndSwapUint32(&w.counter, current, current+1) {
			w.wg.Go(func() error {
				return w.gowalk(pathname)
			})
			return nil
		}
	}

	// if we've reached our limit, continue with this goroutine
	err = w.readdir(pathname)
	if err != nil && w.options.errorCallback != nil {
		err = w.options.errorCallback(pathname, err)
	}
	return err
}

func (w *walker) gowalk(pathname string) error {
	err := w.readdir(pathname)
	if err != nil && w.options.errorCallback != nil {
		err = w.options.errorCallback(pathname, err)
	}

	atomic.AddUint32(&w.counter, ^uint32(0))
	return err
}
