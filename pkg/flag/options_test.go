package flag_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestFlag_Parse(t *testing.T) {
	type kv struct {
		key   string
		value any
	}
	tests := []struct {
		name    string
		flag    *kv
		env     *kv
		want    []string
		wantErr string
	}{
		{
			name: "flag, string slice",
			flag: &kv{
				key: "scan.scanners",
				value: []string{
					"vuln",
					"misconfig",
				},
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "env, string",
			env: &kv{
				key:   "TRIVY_SCANNERS",
				value: "vuln,misconfig",
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "flag, alias",
			flag: &kv{
				key:   "scan.security-checks",
				value: "vulnerability,config",
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "env, alias",
			env: &kv{
				key:   "TRIVY_SECURITY_CHECKS",
				value: "vulnerability,config",
			},
			want: []string{
				string(types.VulnerabilityScanner),
				string(types.MisconfigScanner),
			},
		},
		{
			name: "flag, invalid value",
			flag: &kv{
				key:   "scan.scanners",
				value: "vuln,invalid",
			},
			wantErr: `invalid argument "[vuln invalid]" for "--scanners" flag`,
		},
		{
			name: "env, invalid value",
			env: &kv{
				key:   "TRIVY_SCANNERS",
				value: "vuln,invalid",
			},
			wantErr: `invalid argument "[vuln invalid]" for "--scanners" flag`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)

			if tt.flag != nil {
				viper.Set(tt.flag.key, tt.flag.value)
			} else {
				t.Setenv(tt.env.key, tt.env.value.(string))
			}

			app := &cobra.Command{}
			f := flag.ScannersFlag.Clone()
			f.Add(app)
			require.NoError(t, f.Bind(app))

			err := f.Parse()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, f.Value())
		})
	}
}

func setValue[T comparable](key string, value T) {
	if !lo.IsEmpty(value) {
		viper.Set(key, value)
	}
}

func setSliceValue[T any](key string, value []T) {
	if len(value) > 0 {
		viper.Set(key, value)
	}
}

type Output struct {
	b *bytes.Buffer
}

func (o Output) Messages() []string {
	var messages []string
	for _, line := range strings.Split(o.b.String(), "\n") {
		if line == "" {
			continue
		}
		ss := strings.Split(line, "\t")
		messages = append(messages, strings.Join(ss[2:], "\t"))
	}
	return messages
}

func newLogger(level slog.Level) Output {
	out := bytes.NewBuffer(nil)
	logger := log.New(log.NewHandler(out, &log.Options{Level: level}))
	log.SetDefault(logger)
	return Output{b: out}
}
