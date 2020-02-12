package library

import (
	"testing"
	"time"

	library2 "github.com/aquasecurity/trivy/pkg/detector/library"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/extractor"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Scan(t *testing.T) {
	type detectInput struct {
		imageName string
		filePath  string
		created   time.Time
		libs      []ptypes.Library
	}
	type detectOutput struct {
		vulns []types.DetectedVulnerability
		err   error
	}
	type detect struct {
		input  detectInput
		output detectOutput
	}
	type args struct {
		imageName string
		created   time.Time
		files     extractor.FileMap
	}
	tests := []struct {
		name    string
		args    args
		detect  []detect
		want    map[string][]types.DetectedVulnerability
		wantErr string
	}{
		{
			name: "happy",
			args: args{
				imageName: "alpine:3.10",
				created:   time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
				files: extractor.FileMap{
					"app/Pipfile.lock": []byte(`{
    "_meta": {
        "hash": {
            "sha256": "ad1805ab0e16cf08032c3fe45eeaa29b79e9c196650411977af14e31b12ff0cd"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.7"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.python.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "django": {
            "hashes": [
                "sha256:665457d4146bbd34ae9d2970fa3b37082d7b225b0671bfd24c337458f229db78",
                "sha256:bde46d4dbc410678e89bc95ea5d312dd6eb4c37d0fa0e19c9415cad94addf22f"
            ],
            "index": "pypi",
            "version": "==3.0.0"
        }
    }
}
`),
					"app/package-lock.json": []byte(`{
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "react": {
      "version": "16.8.6",
      "resolved": "https://registry.npmjs.org/react/-/react-16.8.6.tgz",
      "integrity": "sha512-pC0uMkhLaHm11ZSJULfOBqV4tIZkx87ZLvbbQYunNixAAvjnC+snJCg0XQXn9VIsttVsbZP/H/ewzgsd5fxKXw==",
      "requires": {
        "loose-envify": "^1.1.0",
        "object-assign": "^4.1.1",
        "prop-types": "^15.6.2",
        "scheduler": "^0.13.6"
      }
    }
  }
}`),
				},
			},
			detect: []detect{
				{
					input: detectInput{
						imageName: "alpine:3.10",
						filePath:  "app/Pipfile.lock",
						created:   time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
						libs: []ptypes.Library{
							{Name: "django", Version: "3.0.0"},
						},
					},
					output: detectOutput{
						vulns: []types.DetectedVulnerability{
							{VulnerabilityID: "CVE-2019-0001"},
						},
					},
				},
				{
					input: detectInput{
						imageName: "alpine:3.10",
						filePath:  "app/package-lock.json",
						created:   time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
						libs: []ptypes.Library{
							{Name: "react", Version: "16.8.6"},
						},
					},
					output: detectOutput{
						vulns: []types.DetectedVulnerability{
							{VulnerabilityID: "CVE-2019-0002"},
							{VulnerabilityID: "CVE-2019-0003"},
						},
					},
				},
			},
			want: map[string][]types.DetectedVulnerability{
				"app/Pipfile.lock": {{VulnerabilityID: "CVE-2019-0001"}},
				"app/package-lock.json": {
					{VulnerabilityID: "CVE-2019-0002"},
					{VulnerabilityID: "CVE-2019-0003"},
				},
			},
		},
		{
			name: "broken lock file",
			args: args{
				imageName: "alpine:3.10",
				created:   time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
				files: extractor.FileMap{
					"app/Pipfile.lock": []byte(`{broken}`),
				},
			},
			wantErr: "failed to analyze libraries",
		},
		{
			name: "Detect returns an error",
			args: args{
				files: extractor.FileMap{
					"app/package-lock.json": []byte(`{
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "react": {
      "version": "16.8.6",
      "resolved": "https://registry.npmjs.org/react/-/react-16.8.6.tgz",
      "integrity": "sha512-pC0uMkhLaHm11ZSJULfOBqV4tIZkx87ZLvbbQYunNixAAvjnC+snJCg0XQXn9VIsttVsbZP/H/ewzgsd5fxKXw==",
      "requires": {
        "loose-envify": "^1.1.0",
        "object-assign": "^4.1.1",
        "prop-types": "^15.6.2",
        "scheduler": "^0.13.6"
      }
    }
  }
}`),
				},
			},
			detect: []detect{
				{
					input: detectInput{
						filePath: "app/package-lock.json",
						libs: []ptypes.Library{
							{Name: "react", Version: "16.8.6"},
						},
					},
					output: detectOutput{err: xerrors.New("error")},
				},
			},
			wantErr: "failed library scan",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := new(library2.MockDetector)
			for _, d := range tt.detect {
				mockDetector.On("Detect", d.input.imageName, d.input.filePath, d.input.created, d.input.libs).Return(
					d.output.vulns, d.output.err)
			}

			s := Scanner{
				detector: mockDetector,
			}
			got, err := s.Scan(tt.args.imageName, tt.args.created, tt.args.files)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got, tt.name)
			mockDetector.AssertExpectations(t)
		})
	}
}
