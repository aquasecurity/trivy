package flag_test

import (
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestGlobalFlagGroup_NoColorPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		presetNoColor bool
		cliArgs     []string
		wantNoColor bool
	}{
		{
			name:          "explicit --no-color=false overrides NO_COLOR",
			presetNoColor: true,
			cliArgs:       []string{"--no-color=false"},
			wantNoColor:   false,
		},
		{
			name:          "explicit --no-color forces color off",
			presetNoColor: false,
			cliArgs:       []string{"--no-color"},
			wantNoColor:   true,
		},
		{
			name:          "no flag preserves fatih/color state",
			presetNoColor: true,
			cliArgs:       nil,
			wantNoColor:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := color.NoColor
			t.Cleanup(func() { color.NoColor = orig })

			color.NoColor = tt.presetNoColor

			cmd := &cobra.Command{Use: "test"}
			fg := flag.NewGlobalFlagGroup()
			fg.AddFlags(cmd)
			require.NoError(t, cmd.ParseFlags(tt.cliArgs))
			require.NoError(t, fg.Bind(cmd))

			var opts flag.Options
			require.NoError(t, fg.ToOptions(&opts))
			assert.Equal(t, tt.wantNoColor, opts.NoColor)
			assert.Equal(t, tt.wantNoColor, color.NoColor)
		})
	}
}
