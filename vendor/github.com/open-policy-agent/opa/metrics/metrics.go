// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package metrics contains helpers for performance metric management inside the policy engine.
package metrics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	go_metrics "github.com/rcrowley/go-metrics"
)

// Well-known metric names.
const (
	BundleRequest       = "bundle_request"
	ServerHandler       = "server_handler"
	ServerQueryCacheHit = "server_query_cache_hit"
	SDKDecisionEval     = "sdk_decision_eval"
	RegoQueryCompile    = "rego_query_compile"
	RegoQueryEval       = "rego_query_eval"
	RegoQueryParse      = "rego_query_parse"
	RegoModuleParse     = "rego_module_parse"
	RegoDataParse       = "rego_data_parse"
	RegoModuleCompile   = "rego_module_compile"
	RegoPartialEval     = "rego_partial_eval"
	RegoInputParse      = "rego_input_parse"
	RegoLoadFiles       = "rego_load_files"
	RegoLoadBundles     = "rego_load_bundles"
	RegoExternalResolve = "rego_external_resolve"
)

// Info contains attributes describing the underlying metrics provider.
type Info struct {
	Name string `json:"name"` // name is a unique human-readable identifier for the provider.
}

// Metrics defines the interface for a collection of performance metrics in the
// policy engine.
type Metrics interface {
	Info() Info
	Timer(name string) Timer
	Histogram(name string) Histogram
	Counter(name string) Counter
	All() map[string]interface{}
	Clear()
	json.Marshaler
}

type TimerMetrics interface {
	Timers() map[string]interface{}
}

type metrics struct {
	mtx        sync.Mutex
	timers     map[string]Timer
	histograms map[string]Histogram
	counters   map[string]Counter
}

// New returns a new Metrics object.
func New() Metrics {
	m := &metrics{}
	m.Clear()
	return m
}

type metric struct {
	Key   string
	Value interface{}
}

func (*metrics) Info() Info {
	return Info{
		Name: "<built-in>",
	}
}

func (m *metrics) String() string {

	all := m.All()
	sorted := make([]metric, 0, len(all))

	for key, value := range all {
		sorted = append(sorted, metric{
			Key:   key,
			Value: value,
		})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Key < sorted[j].Key
	})

	buf := make([]string, len(sorted))
	for i := range sorted {
		buf[i] = fmt.Sprintf("%v:%v", sorted[i].Key, sorted[i].Value)
	}

	return strings.Join(buf, " ")
}

func (m *metrics) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.All())
}

func (m *metrics) Timer(name string) Timer {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	t, ok := m.timers[name]
	if !ok {
		t = &timer{}
		m.timers[name] = t
	}
	return t
}

func (m *metrics) Histogram(name string) Histogram {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	h, ok := m.histograms[name]
	if !ok {
		h = newHistogram()
		m.histograms[name] = h
	}
	return h
}

func (m *metrics) Counter(name string) Counter {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	c, ok := m.counters[name]
	if !ok {
		zero := counter{}
		c = &zero
		m.counters[name] = c
	}
	return c
}

func (m *metrics) All() map[string]interface{} {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	result := map[string]interface{}{}
	for name, timer := range m.timers {
		result[m.formatKey(name, timer)] = timer.Value()
	}
	for name, hist := range m.histograms {
		result[m.formatKey(name, hist)] = hist.Value()
	}
	for name, cntr := range m.counters {
		result[m.formatKey(name, cntr)] = cntr.Value()
	}
	return result
}

func (m *metrics) Timers() map[string]interface{} {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	ts := map[string]interface{}{}
	for n, t := range m.timers {
		ts[m.formatKey(n, t)] = t.Value()
	}
	return ts
}

func (m *metrics) Clear() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.timers = map[string]Timer{}
	m.histograms = map[string]Histogram{}
	m.counters = map[string]Counter{}
}

func (m *metrics) formatKey(name string, metrics interface{}) string {
	switch metrics.(type) {
	case Timer:
		return "timer_" + name + "_ns"
	case Histogram:
		return "histogram_" + name
	case Counter:
		return "counter_" + name
	default:
		return name
	}
}

// Timer defines the interface for a restartable timer that accumulates elapsed
// time.
type Timer interface {
	Value() interface{}
	Int64() int64
	Start()
	Stop() int64
}

type timer struct {
	mtx   sync.Mutex
	start time.Time
	value int64
}

func (t *timer) Start() {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.start = time.Now()
}

func (t *timer) Stop() int64 {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	delta := time.Since(t.start).Nanoseconds()
	t.value += delta
	return delta
}

func (t *timer) Value() interface{} {
	return t.Int64()
}

func (t *timer) Int64() int64 {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	return t.value
}

// Histogram defines the interface for a histogram with hardcoded percentiles.
type Histogram interface {
	Value() interface{}
	Update(int64)
}

type histogram struct {
	hist go_metrics.Histogram // is thread-safe because of the underlying ExpDecaySample
}

func newHistogram() Histogram {
	// NOTE(tsandall): the reservoir size and alpha factor are taken from
	// https://github.com/rcrowley/go-metrics. They may need to be tweaked in
	// the future.
	sample := go_metrics.NewExpDecaySample(1028, 0.015)
	hist := go_metrics.NewHistogram(sample)
	return &histogram{hist}
}

func (h *histogram) Update(v int64) {
	h.hist.Update(v)
}

func (h *histogram) Value() interface{} {
	values := map[string]interface{}{}
	snap := h.hist.Snapshot()
	percentiles := snap.Percentiles([]float64{
		0.5,
		0.75,
		0.9,
		0.95,
		0.99,
		0.999,
		0.9999,
	})
	values["count"] = snap.Count()
	values["min"] = snap.Min()
	values["max"] = snap.Max()
	values["mean"] = snap.Mean()
	values["stddev"] = snap.StdDev()
	values["median"] = percentiles[0]
	values["75%"] = percentiles[1]
	values["90%"] = percentiles[2]
	values["95%"] = percentiles[3]
	values["99%"] = percentiles[4]
	values["99.9%"] = percentiles[5]
	values["99.99%"] = percentiles[6]
	return values
}

// Counter defines the interface for a monotonic increasing counter.
type Counter interface {
	Value() interface{}
	Incr()
	Add(n uint64)
}

type counter struct {
	c uint64
}

func (c *counter) Incr() {
	atomic.AddUint64(&c.c, 1)
}

func (c *counter) Add(n uint64) {
	atomic.AddUint64(&c.c, n)
}

func (c *counter) Value() interface{} {
	return atomic.LoadUint64(&c.c)
}

func Statistics(num ...int64) interface{} {
	t := newHistogram()
	for _, n := range num {
		t.Update(n)
	}
	return t.Value()
}
