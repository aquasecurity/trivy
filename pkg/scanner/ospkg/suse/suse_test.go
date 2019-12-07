package suse

import (
	"os"
	"testing"
	"time"

	suseoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-oval"
	"github.com/aquasecurity/trivy/pkg/log"

	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	os.Exit(m.Run())
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		clock     clock.Clock
		osFamily  string
		osVersion string
		expected  bool
	}{
		"opensuse.leap42.3": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "opensuse.leap",
			osVersion: "42.3",
			expected:  true,
		},
		"opensuse.leap15": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "opensuse.leap",
			osVersion: "15.0",
			expected:  true,
		},
		"opensuse.leap15.1": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "opensuse.leap",
			osVersion: "15.1",
			expected:  true,
		},
		"opensuse.leap15.1-sametime": {
			clock:     clocktesting.NewFakeClock(time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC)),
			osFamily:  "opensuse.leap",
			osVersion: "15.1",
			expected:  false,
		},
		"sles12.3": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "suse linux enterprise server",
			osVersion: "12.3",
			expected:  false,
		},
		"sles15": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "suse linux enterprise server",
			osVersion: "15",
			expected:  true,
		},
		"unknown": {
			clock:     clocktesting.NewFakeClock(time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC)),
			osFamily:  "oracle",
			osVersion: "unknown",
			expected:  false,
		},
	}

	for testName, v := range vectors {
		s := &Scanner{
			vs:    suseoval.NewVulnSrc(),
			clock: v.clock,
		}
		t.Run(testName, func(t *testing.T) {
			actual := s.IsSupportedVersion(v.osFamily, v.osVersion)
			if actual != v.expected {
				t.Errorf("[%s] got %v, want %v", testName, actual, v.expected)
			}
		})
	}

}
