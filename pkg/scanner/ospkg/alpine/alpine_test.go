package alpine

import (
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, false)
	os.Exit(m.Run())
}

func TestScanner_IsSupportedVersion(t *testing.T) {
	vectors := map[string]struct {
		now       time.Time
		osFamily  string
		osVersion string
		expected  bool
	}{
		"alpine3.6": {
			now:       time.Date(2019, 3, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.6",
			expected:  true,
		},
		"alpine3.6 with EOL": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.6.5",
			expected:  false,
		},
		"alpine3.9": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.9.0",
			expected:  true,
		},
		"alpine3.10": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
			osVersion: "3.10",
			expected:  true,
		},
		"unknown": {
			now:       time.Date(2019, 5, 2, 23, 59, 59, 0, time.UTC),
			osFamily:  "alpine",
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
