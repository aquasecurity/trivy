package ospkg

import (
	"os"
	"testing"
	"time"

	"golang.org/x/xerrors"

	ospkg2 "github.com/aquasecurity/trivy/pkg/detector/ospkg"

	"github.com/stretchr/testify/require"

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

func TestScanner_Scan(t *testing.T) {
	type detectInput struct {
		imageName string
		osFamily  string
		osName    string
		buildTime time.Time
		pkgs      []analyzer.Package
	}
	type detectOutput struct {
		vulns []types.DetectedVulnerability
		eosl  bool
		err   error
	}
	type detect struct {
		input  detectInput
		output detectOutput
	}

	type fields struct {
		imageName string
		created   time.Time
		files     extractor.FileMap
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
				imageName: "alpine:3.10.2",
				created:   time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
				files: extractor.FileMap{
					"/config":            []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:09f2bbe58e774849d74dc1391c2e01731896c745c4aba1ecf69a283bdb4b537a","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"c10d36fa368a7ea673683682666758adf35efe98e10989505f4f566b5b18538f","container_config":{"Hostname":"c10d36fa368a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"/bin/sh\"]"],"ArgsEscaped":true,"Image":"sha256:09f2bbe58e774849d74dc1391c2e01731896c745c4aba1ecf69a283bdb4b537a","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{}},"created":"2019-05-11T00:07:03.510395965Z","docker_version":"18.06.1-ce","history":[{"created":"2019-05-11T00:07:03.358250803Z","created_by":"/bin/sh -c #(nop) ADD file:a86aea1f3a7d68f6ae03397b99ea77f2e9ee901c5c59e59f76f93adbb4035913 in / "},{"created":"2019-05-11T00:07:03.510395965Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:f1b5933fe4b5f49bbe8258745cf396afe07e625bdab3168e364daf7c956b6b81"]}}`),
					"etc/alpine-release": []byte("3.10.2"),
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
					imageName: "alpine:3.10.2",
					osFamily:  "alpine",
					osName:    "3.10.2",
					buildTime: time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
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
				files: extractor.FileMap{
					"etc/alpine-release": []byte("3.10.2"),
					"invalid":            []byte(`invalid`),
				},
			},
			want: want{err: analyzer.ErrPkgAnalysis.Error()},
		},
		{
			name: "Detect returns an error",
			fields: fields{
				imageName: "alpine:3.10",
				created:   time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
				files: extractor.FileMap{
					"/config":            []byte(`{"architecture":"amd64","config":{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"],"ArgsEscaped":true,"Image":"sha256:09f2bbe58e774849d74dc1391c2e01731896c745c4aba1ecf69a283bdb4b537a","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":null},"container":"c10d36fa368a7ea673683682666758adf35efe98e10989505f4f566b5b18538f","container_config":{"Hostname":"c10d36fa368a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ","CMD [\"/bin/sh\"]"],"ArgsEscaped":true,"Image":"sha256:09f2bbe58e774849d74dc1391c2e01731896c745c4aba1ecf69a283bdb4b537a","Volumes":null,"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{}},"created":"2019-05-11T00:07:03.510395965Z","docker_version":"18.06.1-ce","history":[{"created":"2019-05-11T00:07:03.358250803Z","created_by":"/bin/sh -c #(nop) ADD file:a86aea1f3a7d68f6ae03397b99ea77f2e9ee901c5c59e59f76f93adbb4035913 in / "},{"created":"2019-05-11T00:07:03.510395965Z","created_by":"/bin/sh -c #(nop)  CMD [\"/bin/sh\"]","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:f1b5933fe4b5f49bbe8258745cf396afe07e625bdab3168e364daf7c956b6b81"]}}`),
					"etc/alpine-release": []byte("3.10.2"),
					"lib/apk/db/installed": []byte(`C:Q11Ing8/u1VIdY9czSxaDO9wJg72I=
P:musl
V:1.1.22-r3
A:x86_64
`),
				},
			},
			detect: detect{
				input: detectInput{
					imageName: "alpine:3.10",
					osFamily:  "alpine",
					osName:    "3.10.2",
					buildTime: time.Date(2019, 5, 11, 0, 7, 3, 510395965, time.UTC),
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
			mockDetector := new(ospkg2.MockDetector)
			mockDetector.On("Detect", tt.detect.input.imageName, tt.detect.input.osFamily, tt.detect.input.osName,
				tt.detect.input.buildTime, tt.detect.input.pkgs).Return(tt.detect.output.vulns, tt.detect.output.eosl, tt.detect.output.err)

			s := NewScanner(mockDetector)
			got, got1, got2, err := s.Scan(tt.fields.imageName, tt.fields.created, tt.fields.files)

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
