package debian

import (
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
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
		"debian7": {
			now:       time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "7",
			expected:  false,
		},
		"debian8": {
			now:       time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "8.11",
			expected:  true,
		},
		"debian8 eol ends": {
			now:       time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "8.0",
			expected:  false,
		},
		"debian9": {
			now:       time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "9",
			expected:  true,
		},
		"unknown": {
			now:       time.Date(2020, 7, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
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
