package parallel

import (
	"context"

	"github.com/cheggaaa/pb/v3"

	"golang.org/x/sync/errgroup"
)

// Pipeline represents a structure for performing parallel processing.
// T represents the input element type and U represents the output element type.
type Pipeline[T, U any] struct {
	numWorkers int
	items      []T
	onItem     onItem[T, U]
	onResult   onResult[U]
	progress   bool
}

// onItem represents a function type that takes an input element and returns an output element.
type onItem[T, U any] func(T) (U, error)

// onResult represents a function type that takes an output element.
type onResult[U any] func(U) error

func NewPipeline[T, U any](numWorkers int, progress bool, items []T,
	fn1 onItem[T, U], fn2 onResult[U]) Pipeline[T, U] {
	return Pipeline[T, U]{
		numWorkers: numWorkers,
		progress:   progress,
		items:      items,
		onItem:     fn1,
		onResult:   fn2,
	}
}

// Do executes pipeline processing.
// It exits when any error occurs.
func (p *Pipeline[T, U]) Do(ctx context.Context) error {
	// progress bar
	var bar *pb.ProgressBar
	if p.progress {
		bar = pb.StartNew(len(p.items))
		defer bar.Finish()
	}

	g, ctx := errgroup.WithContext(ctx)
	itemCh := make(chan T)

	// Start a goroutine to send input data
	g.Go(func() error {
		defer close(itemCh)
		for _, item := range p.items {
			if p.progress {
				bar.Increment()
			}
			select {
			case itemCh <- item:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	// Generate a channel for sending output data
	results := make(chan U)

	// Start a fixed number of goroutines to process items.
	for i := 0; i < p.numWorkers; i++ {
		g.Go(func() error {
			for item := range itemCh {
				res, err := p.onItem(item)
				if err != nil {
					return err
				}
				select {
				case results <- res:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(results)
	}()

	// Process output data received from the channel
	for res := range results {
		if err := p.onResult(res); err != nil {
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
