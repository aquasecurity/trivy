package scanner

import (
	"fmt"
	"os"

	"github.com/aquasecurity/loading/pkg/bar"
)

type progressTracker struct {
	serviceBar     *bar.Bar
	serviceTotal   int
	serviceCurrent int
	isTTY          bool
}

func newProgressTracker() *progressTracker {
	var isTTY bool
	if stat, err := os.Stdout.Stat(); err == nil {
		isTTY = stat.Mode()&os.ModeCharDevice == os.ModeCharDevice
	}
	return &progressTracker{
		isTTY: isTTY,
	}
}

func (m *progressTracker) Finish() {
	if !m.isTTY || m.serviceBar == nil {
		return
	}
	m.serviceBar.Finish()
}

func (m *progressTracker) IncrementResource() {
	if !m.isTTY {
		return
	}
	m.serviceBar.Increment()
}

func (m *progressTracker) SetTotalResources(i int) {
	if !m.isTTY {
		return
	}
	m.serviceBar.SetTotal(i)
}

func (m *progressTracker) SetTotalServices(i int) {
	m.serviceTotal = i
}

func (m *progressTracker) SetServiceLabel(label string) {
	if !m.isTTY {
		return
	}
	m.serviceBar.SetLabel("└╴" + label)
	m.serviceBar.SetCurrent(0)
}

func (m *progressTracker) FinishService() {
	if !m.isTTY {
		return
	}
	m.serviceCurrent++
	m.serviceBar.Finish()
}

func (m *progressTracker) StartService(name string) {
	if !m.isTTY {
		return
	}
	fmt.Printf("[%d/%d] Scanning %s...\n", m.serviceCurrent+1, m.serviceTotal, name)
	m.serviceBar = bar.New(
		bar.OptionHideOnFinish(true),
		bar.OptionWithAutoComplete(false),
		bar.OptionWithRenderFunc(bar.RenderColoured(0xff, 0x66, 0x00)),
	)
	m.SetServiceLabel("Initializing...")
}
