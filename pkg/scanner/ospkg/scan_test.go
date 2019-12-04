package ospkg

import (
	"os"
	"testing"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/rpc/client/ospkg"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestMain(m *testing.M) {
	log.InitLogger(false, true)
	code := m.Run()
	os.Exit(code)
}

func TestNewScanner(t *testing.T) {
	type args struct {
		remoteURL string
		token     string
		files     extractor.FileMap
	}
	tests := []struct {
		name    string
		args    args
		want    Scanner
		wantErr string
	}{
		{
			name: "happy path: local",
			args: args{
				remoteURL: "",
				token:     "",
				files: extractor.FileMap{
					"etc/alpine-release": []byte(`3.10.2`),
				},
			},
			want: Scanner{
				os: analyzer.OS{
					Name:   "3.10.2",
					Family: "alpine",
				},
				files: extractor.FileMap{
					"etc/alpine-release": []byte(`3.10.2`),
				},
				detector: Detector{},
			},
		},
		{
			name: "happy path: rpc",
			args: args{
				remoteURL: "http://localhost:8080",
				token:     "token",
				files: extractor.FileMap{
					"etc/alpine-release": []byte(`3.10.2`),
				},
			},
			want: Scanner{
				os: analyzer.OS{
					Name:   "3.10.2",
					Family: "alpine",
				},
				files: extractor.FileMap{
					"etc/alpine-release": []byte(`3.10.2`),
				},
				detector: ospkg.DetectClient{},
			},
		},
		{
			name: "unknown error",
			args: args{
				files: extractor.FileMap{
					"etc/unknown-release": []byte(`foo`),
				},
			},
			wantErr: "failed to analyze OS: Unknown OS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewScanner(tt.args.remoteURL, tt.args.token, tt.args.files)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want.os, got.os, tt.name)
			assert.Equal(t, tt.want.files, got.files, tt.name)
			assert.IsType(t, tt.want.detector, got.detector, tt.name)
		})
	}
}

func TestScanner_Scan(t *testing.T) {
	type detectInput struct {
		osFamily string
		osName   string
		pkgs     []analyzer.Package
	}
	type detectOutput struct {
		vulns []types.DetectedVulnerability
		err   error
	}
	type detect struct {
		input  detectInput
		output detectOutput
	}

	type fields struct {
		os    analyzer.OS
		files extractor.FileMap
	}
	type want struct {
		osFamily string
		osName   string
		vulns    []types.DetectedVulnerability
		err      string
	}
	tests := []struct {
		name   string
		fields fields
		detect detect
		want   want
	}{
		{
			name: "happy path",
			fields: fields{
				os: analyzer.OS{
					Name:   "3.10.2",
					Family: "alpine",
				},
				files: extractor.FileMap{
					"lib/apk/db/installed": []byte(`C:Q11Ing8/u1VIdY9czSxaDO9wJg72I=
P:musl
V:1.1.22-r3
A:x86_64
S:368204
I:598016
T:the musl c library (libc) implementation
U:http://www.musl-libc.org/
L:MIT
o:musl
m:Timo Teräs <timo.teras@iki.fi>
t:1565162130
c:0c777cf840e82cdc528651e3f3f8f9dda6b1b028
p:so:libc.musl-x86_64.so.1=1
F:lib
R:libc.musl-x86_64.so.1
a:0:0:777
Z:Q17yJ3JFNypA4mxhJJr0ou6CzsJVI=
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q1TTLtUopPeiF9JrA0cgKQZYggG+c=
F:usr
F:usr/lib
`),
				},
			},
			detect: detect{
				input: detectInput{
					osFamily: "alpine",
					osName:   "3.10.2",
					pkgs: []analyzer.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				output: detectOutput{
					vulns: []types.DetectedVulnerability{
						{VulnerabilityID: "CVE-2019-0001", PkgName: "musl"},
					},
					err: nil,
				},
			},
			want: want{
				osFamily: "alpine",
				osName:   "3.10.2",
				vulns: []types.DetectedVulnerability{
					{VulnerabilityID: "CVE-2019-0001", PkgName: "musl"},
				},
			},
		},
		{
			name: "sad path",
			fields: fields{
				os: analyzer.OS{
					Name:   "3.10.2",
					Family: "alpine",
				},
				files: extractor.FileMap{
					"invalid": []byte(`invalid`),
				},
			},
			want: want{err: analyzer.ErrPkgAnalysis.Error()},
		},
		{
			name: "Detect returns an error",
			fields: fields{
				os: analyzer.OS{
					Name:   "3.10.2",
					Family: "alpine",
				},
				files: extractor.FileMap{
					"lib/apk/db/installed": []byte(`C:Q11Ing8/u1VIdY9czSxaDO9wJg72I=
P:musl
V:1.1.22-r3
A:x86_64
`),
				},
			},
			detect: detect{
				input: detectInput{
					osFamily: "alpine",
					osName:   "3.10.2",
					pkgs: []analyzer.Package{
						{Name: "musl", Version: "1.1.22-r3"},
					},
				},
				output: detectOutput{
					err: xerrors.New("error"),
				},
			},
			want: want{
				err: "failed to detect vulnerabilities",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDetector := new(MockDetector)
			mockDetector.On("Detect", tt.detect.input.osFamily, tt.detect.input.osName,
				tt.detect.input.pkgs).Return(tt.detect.output.vulns, tt.detect.output.err)

			s := Scanner{
				os:       tt.fields.os,
				files:    tt.fields.files,
				detector: mockDetector,
			}
			got, got1, got2, err := s.Scan()

			if tt.want.err != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.want.err, tt.name)
				return
			} else {
				assert.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want.osFamily, got)
			assert.Equal(t, tt.want.osName, got1)
			assert.Equal(t, tt.want.vulns, got2)
			mockDetector.AssertExpectations(t)
		})
	}
}

func Test_mergePkgs(t *testing.T) {
	type args struct {
		pkgs             []analyzer.Package
		pkgsFromCommands []analyzer.Package
	}
	tests := []struct {
		name string
		args args
		want []analyzer.Package
	}{
		{
			name: "happy path",
			args: args{
				pkgs: []analyzer.Package{
					{Name: "foo", Version: "1.2.3"},
					{Name: "bar", Version: "3.4.5"},
					{Name: "baz", Version: "6.7.8"},
				},
				pkgsFromCommands: []analyzer.Package{
					{Name: "bar", Version: "1.1.1"},
					{Name: "hoge", Version: "9.0.1"},
				},
			},
			want: []analyzer.Package{
				{Name: "foo", Version: "1.2.3"},
				{Name: "bar", Version: "3.4.5"},
				{Name: "baz", Version: "6.7.8"},
				{Name: "hoge", Version: "9.0.1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergePkgs(tt.args.pkgs, tt.args.pkgsFromCommands)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
