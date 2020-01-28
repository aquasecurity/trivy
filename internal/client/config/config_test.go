package config

import (
	"flag"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Config
	}{
		{
			name: "happy path",
			args: []string{"-quiet", "--cache-dir", "/tmp/test"},
			want: Config{
				Quiet:    true,
				CacheDir: "/tmp/test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{}
			set := flag.NewFlagSet("test", 0)
			set.Bool("quiet", false, "")
			set.String("cache-dir", "", "")

			c := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			got, err := New(c)

			// avoid to compare these values because these values are pointer
			tt.want.context = c
			tt.want.logger = got.logger

			assert.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestConfig_Init(t *testing.T) {
	type fields struct {
		context        *cli.Context
		Quiet          bool
		NoProgress     bool
		Debug          bool
		CacheDir       string
		Reset          bool
		DownloadDBOnly bool
		SkipUpdate     bool
		ClearCache     bool
		Input          string
		output         string
		Format         string
		Template       string
		Timeout        time.Duration
		vulnType       string
		Light          bool
		severities     string
		IgnoreFile     string
		IgnoreUnfixed  bool
		ExitCode       int
		ImageName      string
		VulnType       []string
		Output         *os.File
		Severities     []dbTypes.Severity
		AppVersion     string
		onlyUpdate     string
		refresh        bool
		autoRefresh    bool
		token          string
		tokenHeader    string
	}
	tests := []struct {
		name    string
		fields  fields
		args    []string
		logs    []string
		want    Config
		wantErr string
	}{
		{
			name: "happy path",
			fields: fields{
				severities:  "CRITICAL",
				vulnType:    "os",
				Quiet:       true,
				token:       "foobar",
				tokenHeader: "Trivy-Token",
			},
			args: []string{"alpine:3.10"},
			want: Config{
				AppVersion:  "0.0.0",
				Severities:  []dbTypes.Severity{dbTypes.SeverityCritical},
				severities:  "CRITICAL",
				ImageName:   "alpine:3.10",
				VulnType:    []string{"os"},
				vulnType:    "os",
				Output:      os.Stdout,
				Quiet:       true,
				token:       "foobar",
				tokenHeader: "Trivy-Token",
				CustomHeaders: http.Header{
					"Trivy-Token": []string{"foobar"},
				},
			},
		},
		{
			name: "happy path with an unknown severity",
			fields: fields{
				severities: "CRITICAL,INVALID",
				vulnType:   "os,library",
			},
			args: []string{"centos:7"},
			logs: []string{
				"unknown severity option: unknown severity: INVALID",
			},
			want: Config{
				AppVersion:    "0.0.0",
				Severities:    []dbTypes.Severity{dbTypes.SeverityCritical, dbTypes.SeverityUnknown},
				severities:    "CRITICAL,INVALID",
				ImageName:     "centos:7",
				VulnType:      []string{"os", "library"},
				vulnType:      "os,library",
				Output:        os.Stdout,
				CustomHeaders: make(http.Header),
			},
		},
		{
			name: "with latest tag",
			fields: fields{
				onlyUpdate: "alpine",
				severities: "LOW",
				vulnType:   "os,library",
			},
			args: []string{"gcr.io/distroless/base"},
			logs: []string{
				"You should avoid using the :latest tag as it is cached. You need to specify '--clear-cache' option when :latest image is changed",
			},
			want: Config{
				AppVersion:    "0.0.0",
				Severities:    []dbTypes.Severity{dbTypes.SeverityLow},
				severities:    "LOW",
				ImageName:     "gcr.io/distroless/base",
				VulnType:      []string{"os", "library"},
				vulnType:      "os,library",
				Output:        os.Stdout,
				CustomHeaders: make(http.Header),
			},
		},
		{
			name: "sad: multiple image names",
			fields: fields{
				severities: "MEDIUM",
			},
			args: []string{"centos:7", "alpine:3.10"},
			logs: []string{
				"multiple images cannot be specified",
			},
			wantErr: "arguments error",
		},
		{
			name: "sad: no image name",
			fields: fields{
				severities: "MEDIUM",
			},
			logs: []string{
				"trivy requires at least 1 argument or --input option",
			},
			wantErr: "arguments error",
		},
		{
			name: "sad: invalid image name",
			fields: fields{
				severities: "HIGH",
			},
			args:    []string{`!"#$%&'()`},
			wantErr: "invalid image: parsing image",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, obs := observer.New(zap.InfoLevel)
			logger := zap.New(core)

			app := cli.NewApp()
			set := flag.NewFlagSet("test", 0)
			ctx := cli.NewContext(app, set, nil)
			_ = set.Parse(tt.args)

			c := &Config{
				context:       ctx,
				logger:        logger.Sugar(),
				Quiet:         tt.fields.Quiet,
				Debug:         tt.fields.Debug,
				CacheDir:      tt.fields.CacheDir,
				ClearCache:    tt.fields.ClearCache,
				Input:         tt.fields.Input,
				output:        tt.fields.output,
				Format:        tt.fields.Format,
				Template:      tt.fields.Template,
				Timeout:       tt.fields.Timeout,
				vulnType:      tt.fields.vulnType,
				severities:    tt.fields.severities,
				IgnoreFile:    tt.fields.IgnoreFile,
				IgnoreUnfixed: tt.fields.IgnoreUnfixed,
				ExitCode:      tt.fields.ExitCode,
				ImageName:     tt.fields.ImageName,
				Output:        tt.fields.Output,
				token:         tt.fields.token,
				tokenHeader:   tt.fields.tokenHeader,
			}

			err := c.Init()

			// tests log messages
			var gotMessages []string
			for _, entry := range obs.AllUntimed() {
				gotMessages = append(gotMessages, entry.Message)
			}
			assert.Equal(t, tt.logs, gotMessages, tt.name)

			// test the error
			switch {
			case tt.wantErr != "":
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			default:
				assert.NoError(t, err, tt.name)
			}

			tt.want.context = ctx
			tt.want.logger = logger.Sugar()
			assert.Equal(t, &tt.want, c, tt.name)
		})
	}
}

func Test_splitCustomHeaders(t *testing.T) {
	type args struct {
		headers []string
	}
	tests := []struct {
		name string
		args args
		want http.Header
	}{
		{
			name: "happy path",
			args: args{
				headers: []string{"x-api-token:foo bar", "Authorization:user:password"},
			},
			want: http.Header{
				"X-Api-Token":   []string{"foo bar"},
				"Authorization": []string{"user:password"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitCustomHeaders(tt.args.headers); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCustomHeaders() = %v, want %v", got, tt.want)
			}
		})
	}
}
