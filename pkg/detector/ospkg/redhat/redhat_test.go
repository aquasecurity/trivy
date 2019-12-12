package redhat

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
		"centos5": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "5.0",
			expected:  false,
		},
		"centos6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "6.7",
			expected:  true,
		},
		"centos6 (eol ends)": {
			now:       time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "6.7",
			expected:  false,
		},
		"centos7": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "7.5",
			expected:  true,
		},
		"centos8": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "8.0",
			expected:  true,
		},
		"two dots": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "centos",
			osVersion: "8.0.1",
			expected:  true,
		},
		"redhat5": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "5.0",
			expected:  true,
		},
		"redhat6": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "6.7",
			expected:  true,
		},
		"redhat6 (eol ends)": {
			now:       time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "6.7",
			expected:  false,
		},
		"redhat7": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "7.5",
			expected:  true,
		},
		"redhat8": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "8.0",
			expected:  true,
		},
		"no dot": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "redhat",
			osVersion: "8",
			expected:  true,
		},
		"debian": {
			now:       time.Date(2019, 5, 31, 23, 59, 59, 0, time.UTC),
			osFamily:  "debian",
			osVersion: "8",
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
