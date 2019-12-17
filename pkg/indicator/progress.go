package indicator

import (
	"io"

	"github.com/cheggaaa/pb/v3"
)

type ProgressBar struct {
	quiet bool
}

func NewProgressBar(quiet bool) ProgressBar {
	return ProgressBar{quiet: quiet}
}

func (p ProgressBar) Start(total int64) Bar {
	if p.quiet {
		return Bar{}
	}
	bar := pb.Full.Start64(total)
	return Bar{bar: bar}
}

type Bar struct {
	bar *pb.ProgressBar
}

func (b Bar) NewProxyReader(r io.Reader) io.Reader {
	if b.bar == nil {
		return r
	}
	return b.bar.NewProxyReader(r)
}
func (b Bar) Finish() {
	if b.bar == nil {
		return
	}
	b.bar.Finish()
}
