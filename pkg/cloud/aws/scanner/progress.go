package scanner

import (
	"fmt"

	"github.com/liamg/loading/pkg/bar"
)

type progressTracker struct {
	serviceBar     *bar.Bar
	serviceTotal   int
	serviceCurrent int
}

func newProgressTracker() *progressTracker {
	return &progressTracker{}
}

func (m *progressTracker) Finish() {
	if m.serviceBar != nil {
		m.serviceBar.Finish()
	}
}

func (m *progressTracker) IncrementResource() {
	m.serviceBar.Increment()
}

func (m *progressTracker) SetTotalResources(i int) {
	m.serviceBar.SetTotal(i)
}

func (m *progressTracker) SetTotalServices(i int) {
	m.serviceTotal = i
}

func (m *progressTracker) SetServiceLabel(label string) {
	m.serviceBar.SetLabel("└╴" + label)
	m.serviceBar.SetCurrent(0)
}

func (m *progressTracker) FinishService() {
	m.serviceCurrent++
	m.serviceBar.Finish()
}

func (m *progressTracker) StartService(name string) {
	fmt.Printf("[%d/%d] Scanning %s...\n", m.serviceCurrent+1, m.serviceTotal, name)
	m.serviceBar = bar.New(
		bar.OptionHideOnFinish(true),
		bar.OptionWithAutoComplete(false),
		bar.OptionWithRenderFunc(bar.RenderColoured(0xff, 0x66, 0x00)),
	)
	m.SetServiceLabel("Initialising...")
}
