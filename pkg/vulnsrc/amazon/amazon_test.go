package amazon

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aquasecurity/vuln-list-update/amazon"

	"github.com/aquasecurity/trivy/pkg/utils"

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

func TestConstructVersion(t *testing.T) {
	type inputCombination struct {
		epoch   string
		version string
		release string
	}

	testCases := []struct {
		name            string
		inc             inputCombination
		expectedVersion string
	}{
		{
			name: "happy path",
			inc: inputCombination{
				epoch:   "1",
				version: "2",
				release: "master",
			},
			expectedVersion: "2-master",
		},
		{
			name: "no epoch",
			inc: inputCombination{
				version: "2",
				release: "master",
			},
			expectedVersion: "2-master",
		},
		{
			name: "no release",
			inc: inputCombination{
				epoch:   "",
				version: "2",
			},
			expectedVersion: "2",
		},
		{
			name: "no epoch and release",
			inc: inputCombination{
				version: "2",
			},
			expectedVersion: "2",
		},
		{
			name:            "no epoch release or version",
			inc:             inputCombination{},
			expectedVersion: "",
		},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.expectedVersion, constructVersion(tc.inc.epoch, tc.inc.version, tc.inc.release), tc.name)
	}
}

func TestConfig_WalkFunc(t *testing.T) {
	testCases := []struct {
		name             string
		ioReader         io.Reader
		inputPath        string
		expectedALASList []alas
		expectedError    error
		expectedLogs     []string
	}{
		{
			name: "happy path",
			ioReader: strings.NewReader(`{
"id":"123",
"severity":"high"
}`),
			inputPath: "1/2/1",
			expectedALASList: []alas{
				{
					Version: "2",
					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "high",
					},
				},
			},
			expectedError: nil,
		},
		{
			name:             "amazon returns invalid json",
			ioReader:         strings.NewReader(`invalidjson`),
			inputPath:        "1/2/1",
			expectedALASList: []alas(nil),
			expectedError:    errors.New("failed to decode amazon JSON: invalid character 'i' looking for beginning of value"),
		},
		{
			name:          "unsupported amazon version",
			inputPath:     "foo/bar/baz",
			expectedError: nil,
			expectedLogs:  []string{"unsupported amazon version: bar"},
		},
		{
			name:          "empty path",
			inputPath:     "",
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		zc, recorder := observer.New(zapcore.DebugLevel)
		log.Logger = zap.New(zc).Sugar()

		ac := Config{
			lg:  log.Logger,
			bar: utils.PbStartNew(1),
		}

		err := ac.walkFunc(tc.ioReader, tc.inputPath)
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}

		assert.Equal(t, tc.expectedALASList, ac.alasList, tc.name)

		allLogs := getAllLoggedLogs(recorder)
		assert.Equal(t, tc.expectedLogs, allLogs, tc.name)
	}

}

type fakeVulnDB struct {
	put func(*bbolt.Tx, string, string, vulnerability.Vulnerability) error
}

func (fvdb fakeVulnDB) Update(string, string, vulnerability.Vulnerability) error {
	panic("implement me")
}

func (fvdb fakeVulnDB) BatchUpdate(func(bucket *bbolt.Bucket) error) error {
	panic("implement me")
}

func (fvdb fakeVulnDB) Get(string) (map[string]vulnerability.Vulnerability, error) {
	panic("implement me")
}

func (fvdb fakeVulnDB) Put(tx *bbolt.Tx, cveID, source string, vuln vulnerability.Vulnerability) error {
	if fvdb.put != nil {
		return fvdb.put(tx, cveID, source, vuln)
	}
	return nil
}

func TestConfig_CommitFunc(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ac := Config{
			dbc: MockDBConfig{},
			alasList: []alas{
				{
					Version: "123",
					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "high",
						CveIDs:   []string{"CVE-2020-0001"},
						References: []amazon.Reference{
							{
								ID:    "fooref",
								Href:  "http://foo.bar/baz",
								Title: "bartitle",
							},
						},
						Packages: []amazon.Package{
							{
								Name:    "testpkg",
								Epoch:   "123",
								Version: "456",
								Release: "testing",
							},
						},
					},
				},
			},
			vdb: fakeVulnDB{},
		}
		assert.NoError(t, ac.commitFunc(&bbolt.Tx{
			WriteFlag: 0,
		}))
	})

	t.Run("failed to save Amazon advisory, PutNestedBucket() return an error", func(t *testing.T) {
		ac := Config{
			dbc: MockDBConfig{
				putnestedbucket: func(tx *bbolt.Tx, s string, s2 string, s3 string, i interface{}) error {
					return errors.New("putnestedbucket failed to save")
				},
			},
			alasList: []alas{
				{
					Version: "123",
					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "high",
						CveIDs:   []string{"CVE-2020-0001"},
						References: []amazon.Reference{
							{
								ID:    "fooref",
								Href:  "http://foo.bar/baz",
								Title: "bartitle",
							},
						},
						Packages: []amazon.Package{
							{
								Name:    "testpkg",
								Epoch:   "123",
								Version: "456",
								Release: "testing",
							},
						},
					},
				},
			},
		}
		assert.Equal(t, "failed to save amazon advisory: putnestedbucket failed to save", ac.commitFunc(&bbolt.Tx{
			WriteFlag: 0,
		}).Error())
	})

	t.Run("failed to save Amazon advisory, PutNestedBucket() return an error", func(t *testing.T) {
		ac := Config{
			dbc: MockDBConfig{},
			vdb: fakeVulnDB{put: func(tx *bbolt.Tx, s string, s2 string, i vulnerability.Vulnerability) error {
				return errors.New("failed to commit to db")
			}},
			alasList: []alas{
				{
					Version: "123",
					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "high",
						CveIDs:   []string{"CVE-2020-0001"},
						References: []amazon.Reference{
							{
								ID:    "fooref",
								Href:  "http://foo.bar/baz",
								Title: "bartitle",
							},
						},
						Packages: []amazon.Package{
							{
								Name:    "testpkg",
								Epoch:   "123",
								Version: "456",
								Release: "testing",
							},
						},
					},
				},
			},
		}
		assert.Equal(t, "failed to save amazon vulnerability: failed to commit to db", ac.commitFunc(&bbolt.Tx{
			WriteFlag: 0,
		}).Error())
	})
}
