package mertics

import (
	"fmt"
	"sync/atomic"
	"time"
)

type Metrics struct {
	CommitsProcessed       int32
	FilesProcessed         int32
	TransgressionsFound    int32
	TransgressionsIgnored  int32
	TransgressionsReported int32
	startTime              time.Time
	endTime                time.Time
}

func NewMetrics() *Metrics {
	return &Metrics{}
}

func (m *Metrics) IncrementCommitsProcessed() {
	atomic.AddInt32(&m.CommitsProcessed, 1)
}

func (m *Metrics) IncrementFilesProcessed() {
	atomic.AddInt32(&m.FilesProcessed, 1)
}

func (m *Metrics) IncrementTransgressionsFound() {
	atomic.AddInt32(&m.TransgressionsFound, 1)
}

func (m *Metrics) IncrementTransgressionsIgnored() {
	atomic.AddInt32(&m.TransgressionsIgnored, 1)
}

func (m *Metrics) IncrementTransgressionsReported() {
	atomic.AddInt32(&m.TransgressionsReported, 1)
}

func (m *Metrics) StartTimer() {
	m.startTime = time.Now()
}

func (m *Metrics) StopTimer() {
	m.endTime = time.Now()
}

func (m *Metrics) Duration() (float64, error) {
	if m.startTime.IsZero() || m.endTime.IsZero() {
		return 0, fmt.Errorf("start time and end time are not set")
	}
	return m.endTime.Sub(m.startTime).Seconds(), nil
}
