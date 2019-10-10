package amazon

import (
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/etcd-io/bbolt"

	"go.uber.org/zap/zaptest/observer"
)

type MockDBConfig struct { // TODO: Move this into vulnerability/db pkg
	setversion      func(string) error
	update          func(string, string, interface{}) error
	batchupdate     func(func(*bbolt.Tx) error) error
	putnestedbucket func(*bbolt.Tx, string, string, string, interface{}) error
	foreach         func(string, string) (map[string][]byte, error)
}

func (mdbc MockDBConfig) SetVersion(a string) error {
	if mdbc.setversion != nil {
		return mdbc.setversion(a)
	}
	return nil
}

func (mdbc MockDBConfig) Update(a string, b string, c interface{}) error {
	if mdbc.update != nil {
		return mdbc.update(a, b, c)
	}
	return nil
}

func (mdbc MockDBConfig) BatchUpdate(f func(*bbolt.Tx) error) error {
	if mdbc.batchupdate != nil {
		return mdbc.batchupdate(f)
	}
	return nil
}

func (mdbc MockDBConfig) PutNestedBucket(a *bbolt.Tx, b string, c string, d string, e interface{}) error {
	if mdbc.putnestedbucket != nil {
		return mdbc.putnestedbucket(a, b, c, d, e)
	}
	return nil
}

func (mdbc MockDBConfig) ForEach(a string, b string) (map[string][]byte, error) {
	if mdbc.foreach != nil {
		return mdbc.foreach(a, b)
	}
	return map[string][]byte{}, nil
}

// TODO: DRY
func getAllLoggedLogs(recorder *observer.ObservedLogs) []string {
	allLogs := recorder.AllUntimed()
	var loggedMessages []string
	for _, l := range allLogs {
		loggedMessages = append(loggedMessages, l.Message)
	}
	return loggedMessages
}

func TestConfig_Update(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		zc, recorder := observer.New(zapcore.DebugLevel)
		log.Logger = zap.New(zc).Sugar()

		ac := Config{
			lg:  log.Logger,
			dbc: MockDBConfig{},
		}

		assert.NoError(t, ac.Update("testdata", map[string]struct{}{"amazon": {}}))
		allLogs := getAllLoggedLogs(recorder)
		assert.Equal(t, allLogs, []string{"Amazon Linux AMI Security Advisory updated files: 1", "Saving amazon DB"})
	})

	// FIXME: This test panics if cache doesn't exist yet
	//t.Run("cache dir doesnt exist", func(t *testing.T) {
	//	zc, recorder := observer.New(zapcore.DebugLevel)
	//	log.Logger = zap.New(zc).Sugar()
	//
	//	ac := Config{
	//		lg:  log.Logger,
	//		dbc: MockDBConfig{},
	//	}
	//
	//	assert.NoError(t, ac.Update("badpathdoesnotexist", map[string]struct{}{"amazon": {}}))
	//	allLogs := getAllLoggedLogs(recorder)
	//	assert.Equal(t, allLogs, []string{"Amazon Linux AMI Security Advisory updated files: 1", "Saving amazon DB"})
	//})

	t.Run("filewalker errors out", func(t *testing.T) {
		zc, recorder := observer.New(zapcore.DebugLevel)
		log.Logger = zap.New(zc).Sugar()

		oldFileWalker := fileWalker // TODO: Remove once utils.go exposes an interface
		defer func() {
			fileWalker = oldFileWalker
		}()

		fileWalker = func(root string, targetFiles map[string]struct{}, walkFn func(r io.Reader, path string) error) error {
			return errors.New("fileWalker errored out")
		}

		ac := Config{
			lg:  log.Logger,
			dbc: MockDBConfig{},
		}

		assert.Equal(t, "error in amazon walk: fileWalker errored out", ac.Update("testdata", map[string]struct{}{"amazon": {}}).Error())
		allLogs := getAllLoggedLogs(recorder)
		assert.NotContains(t, allLogs, "Saving amazon DB")
	})

	t.Run("unable to save amazon defintions", func(t *testing.T) {
		zc, _ := observer.New(zapcore.DebugLevel)
		log.Logger = zap.New(zc).Sugar()

		oldFileWalker := fileWalker // TODO: Remove once utils.go exposes an interface
		defer func() {
			fileWalker = oldFileWalker
		}()

		fileWalker = func(root string, targetFiles map[string]struct{}, walkFn func(r io.Reader, path string) error) error {
			return nil
		}

		ac := Config{
			lg: log.Logger,
			dbc: MockDBConfig{
				batchupdate: func(i func(*bbolt.Tx) error) error {
					return errors.New("unable to batch update")
				},
			},
		}

		assert.Equal(t, "error in amazon save: error in batch update: unable to batch update", ac.Update("testdata", map[string]struct{}{"amazon": {}}).Error())
	})
}

func TestConfig_Get(t *testing.T) {
	testCases := []struct {
		name          string
		forEachFunc   func(s string, s2 string) (bytes map[string][]byte, e error)
		expectedError error
		expectedVulns []vulnerability.Advisory
	}{
		{
			name: "happy path",
			forEachFunc: func(s string, s2 string) (bytes map[string][]byte, e error) {
				b, _ := json.Marshal(vulnerability.Advisory{VulnerabilityID: "123", FixedVersion: "2.0.0"})
				return map[string][]byte{"advisory1": b}, nil
			},
			expectedError: nil,
			expectedVulns: []vulnerability.Advisory{{VulnerabilityID: "123", FixedVersion: "2.0.0"}},
		},
		{
			name: "no advisories are returned",
			forEachFunc: func(s string, s2 string) (bytes map[string][]byte, e error) {
				return map[string][]byte{}, nil
			},
			expectedError: nil,
			expectedVulns: []vulnerability.Advisory(nil),
		},
		{
			name: "amazon forEach return an error",
			forEachFunc: func(s string, s2 string) (bytes map[string][]byte, e error) {
				return nil, errors.New("foreach func returned an error")
			},
			expectedError: errors.New("error in amazon foreach: foreach func returned an error"),
			expectedVulns: nil,
		},
		{
			name: "failed to unmarshal amazon json",
			forEachFunc: func(s string, s2 string) (bytes map[string][]byte, e error) {
				return map[string][]byte{"foo": []byte(`badbar`)}, nil
			},
			expectedError: errors.New("failed to unmarshal amazon JSON: invalid character 'b' looking for beginning of value"),
			expectedVulns: nil,
		},
	}

	for _, tc := range testCases {
		ac := Config{
			dbc: MockDBConfig{foreach: tc.forEachFunc},
		}
		vuls, err := ac.Get("1.1.0", "testpkg")
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}

		assert.Equal(t, tc.expectedVulns, vuls, tc.name)
	}
}

func TestSeverityFromPriority(t *testing.T) {
	testCases := map[string]vulnerability.Severity{
		"low":       vulnerability.SeverityLow,
		"medium":    vulnerability.SeverityMedium,
		"important": vulnerability.SeverityHigh,
		"critical":  vulnerability.SeverityCritical,
		"unknown":   vulnerability.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromPriority(k))
	}
}
