package utils

import (
	"io"
	"time"

	"github.com/briandowns/spinner"
	pb "github.com/cheggaaa/pb/v3"
)

var (
	Quiet = false
)

type Spinner struct {
	client *spinner.Spinner
}

func NewSpinner(suffix string) *Spinner {
	if Quiet {
		return &Spinner{}
	}
	s := spinner.New(spinner.CharSets[36], 100*time.Millisecond)
	s.Suffix = suffix
	return &Spinner{client: s}
}

func (s *Spinner) Start() {
	if s.client == nil {
		return
	}
	s.client.Start()
}
func (s *Spinner) Stop() {
	if s.client == nil {
		return
	}
	s.client.Stop()
}

type ProgressBar struct {
	quiet bool
	bar   *pb.ProgressBar
}

func NewProgressBar(quiet bool) ProgressBar {
	return ProgressBar{quiet: quiet}
}

func (p ProgressBar) Start(total int64) *ProgressBar {
	if p.quiet {
		return &ProgressBar{}
	}
	bar := pb.Full.Start64(total)
	return &ProgressBar{bar: bar}
}

func (p *ProgressBar) NewProxyReader(r io.Reader) io.Reader {
	if p.quiet {
		return r
	}
	return p.bar.NewProxyReader(r)
}
func (p *ProgressBar) Finish() {
	if p.quiet {
		return
	}
	p.bar.Finish()
}
