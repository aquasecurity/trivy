package oracle

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
		"oracle3": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "3",
			expected:  false,
		},
		"oracle4": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "4",
			expected:  false,
		},
		"oracle5": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "5",
			expected:  false,
		},
		"oracle6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "6",
			expected:  true,
		},
		"oracle7": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "7",
			expected:  true,
		},
		"oracle7.6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "7.6",
			expected:  true,
		},
		"oracle8": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
			osVersion: "8",
			expected:  true,
		},
		"unknown": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "oracle",
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
