package amazon

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/mock"

	"github.com/aquasecurity/trivy/pkg/db"

	"github.com/aquasecurity/vuln-list-update/amazon"

	"github.com/aquasecurity/trivy/pkg/utils"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	err := log.InitLogger(false, true)
	if err != nil {
		log.Fatal(err)
	}
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name           string
		cacheDir       string
		batchUpdateErr error
		expectedError  error
		expectedVulns  []vulnerability.Advisory
	}{
		{
			name:          "happy path",
			cacheDir:      "testdata",
			expectedError: nil,
		},
		{
			name:          "cache dir doesnt exist",
			cacheDir:      "badpathdoesnotexist",
			expectedError: errors.New("error in amazon walk: error in file walk: lstat badpathdoesnotexist/amazon: no such file or directory"),
		},
		{
			name:           "unable to save amazon defintions",
			cacheDir:       "testdata",
			batchUpdateErr: errors.New("unable to batch update"),
			expectedError:  errors.New("error in amazon save: error in batch update: unable to batch update"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("BatchUpdate", mock.Anything).Return(tc.batchUpdateErr)
			ac := VulnSrc{dbc: mockDBConfig}

			err := ac.Update(tc.cacheDir, map[string]struct{}{"amazon": {}})
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type forEachReturn struct {
		b   map[string][]byte
		err error
	}
	testCases := []struct {
		name          string
		forEachFunc   forEachReturn
		expectedError error
		expectedVulns []vulnerability.Advisory
	}{
		{
			name: "happy path",
			forEachFunc: forEachReturn{
				b: map[string][]byte{
					"advisory1": []byte(`{"VulnerabilityID":"123","FixedVersion":"2.0.0"}`),
				},
				err: nil,
			},
			expectedError: nil,
			expectedVulns: []vulnerability.Advisory{{VulnerabilityID: "123", FixedVersion: "2.0.0"}},
		},
		{
			name:          "no advisories are returned",
			forEachFunc:   forEachReturn{b: nil, err: nil},
			expectedError: nil,
			expectedVulns: []vulnerability.Advisory(nil),
		},
		{
			name:          "amazon forEach return an error",
			forEachFunc:   forEachReturn{b: nil, err: errors.New("foreach func returned an error")},
			expectedError: errors.New("error in amazon foreach: foreach func returned an error"),
			expectedVulns: nil,
		},
		{
			name:          "failed to unmarshal amazon json",
			forEachFunc:   forEachReturn{b: map[string][]byte{"foo": []byte(`badbar`)}, err: nil},
			expectedError: errors.New("failed to unmarshal amazon JSON: invalid character 'b' looking for beginning of value"),
			expectedVulns: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("ForEach", mock.Anything, mock.Anything).Return(
				tc.forEachFunc.b, tc.forEachFunc.err,
			)
			ac := VulnSrc{dbc: mockDBConfig}

			vuls, err := ac.Get("1.1.0", "testpkg")
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			assert.Equal(t, tc.expectedVulns, vuls, tc.name)
		})
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
				epoch:   "2",
				version: "3",
				release: "master",
			},
			expectedVersion: "2:3-master",
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

func TestVulnSrc_WalkFunc(t *testing.T) {
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
		t.Run(tc.name, func(t *testing.T) {
			ac := VulnSrc{
				bar: utils.PbStartNew(1),
			}

			err := ac.walkFunc(tc.ioReader, tc.inputPath)
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			assert.Equal(t, tc.expectedALASList, ac.alasList, tc.name)
		})
	}
}

func TestVulnSrc_CommitFunc(t *testing.T) {
	testCases := []struct {
		name               string
		alasList           []alas
		putNestedBucketErr error
		putErr             error
		expectedError      error
	}{
		{
			name: "happy path",
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
		},
		{
			name: "failed to save Amazon advisory, PutNestedBucket() return an error",
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
			putNestedBucketErr: errors.New("putnestedbucket failed to save"),
			expectedError:      errors.New("failed to save amazon advisory: putnestedbucket failed to save"),
		},
		{
			name: "failed to save Amazon advisory, Put() return an error",
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
			putErr:        errors.New("failed to commit to db"),
			expectedError: errors.New("failed to save amazon vulnerability: failed to commit to db"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("PutNestedBucket",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
				tc.putNestedBucketErr,
			)
			mockVulnDB := new(vulnerability.MockVulnDB)
			mockVulnDB.On(
				"Put", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
				tc.putErr,
			)

			vs := VulnSrc{dbc: mockDBConfig, vdb: mockVulnDB, alasList: tc.alasList}

			err := vs.commitFunc(&bolt.Tx{WriteFlag: 0})
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}
