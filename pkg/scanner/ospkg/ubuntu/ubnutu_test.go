package ubuntu

import (
	"os"
	"testing"
	"time"

	"github.com/knqyf263/trivy/pkg/log"
)

func TestMain(m *testing.M) {
	log.InitLogger(false)
	os.Exit(m.Run())
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		now       time.Time
		osFamily  string
		osVersion string
		expected  bool
	}{
		"ubuntu12.04 eol ends": {
			now:       time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "12.04",
			expected:  true,
		},
		"ubuntu12.04": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "12.04",
			expected:  false,
		},
		"ubuntu12.10": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "12.10",
			expected:  false,
		},
		"ubuntu18.04": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "18.04",
			expected:  true,
		},
		"ubuntu19.04": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "19.04",
			expected:  true,
		},
		"unknown": {
			now:       time.Date(2019, 4, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "ubuntu",
			osVersion: "unknown",
			expected:  false,
		},
	}

	for testName, v := range vectors {
		s := NewScanner()
		t.Run(testName, func(t *testing.T) {
			actual := s.isSupportedVersion(v.now, v.osFamily, v.osVersion)
			if actual != v.expected {
				t.Errorf("[%s] got %v, want %v", testName, actual, v.expected)
			}
		})
	}
}
