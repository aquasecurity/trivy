package indicator

import (
	"io"

	"github.com/cheggaaa/pb/v3"
)

// ProgressBar exports method to track the progress of jobs
type ProgressBar struct {
	quiet bool
}

// NewProgressBar is the factory method to return progressBar object
func NewProgressBar(quiet bool) ProgressBar {
	return ProgressBar{quiet: quiet}
}

// Start starts the progress tracking
func (p ProgressBar) Start(total int64) Bar {
	if p.quiet {
		return Bar{}
	}
	bar := pb.Full.Start64(total)
	return Bar{bar: bar}
}

// Bar is the proxy progress bar
type Bar struct {
	bar *pb.ProgressBar
}

// NewProxyReader is the factory method to track the progress
func (b Bar) NewProxyReader(r io.Reader) io.Reader {
	if b.bar == nil {
		return r
	}
	return b.bar.NewProxyReader(r)
}

// Finish finishes the progress tracking
func (b Bar) Finish() {
	if b.bar == nil {
		return
	}
	b.bar.Finish()
}
