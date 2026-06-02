package table

import (
	"bytes"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestColorEnabled(t *testing.T) {
	tests := []struct {
		name         string
		mode         types.ColorMode
		wantTerminal bool
		wantNoColor  bool
	}{
		{
			name:         "always forces styled output on and color globally enabled",
			mode:         types.ColorAlways,
			wantTerminal: true,
			wantNoColor:  false,
		},
		{
			name:         "never forces styled output off and color globally disabled",
			mode:         types.ColorNever,
			wantTerminal: false,
			wantNoColor:  true,
		},
		{
			name:         "auto falls back to TTY detection (a buffer is never a terminal)",
			mode:         types.ColorAuto,
			wantTerminal: false,
		},
		{
			name:         "empty mode behaves like auto for backward compatibility",
			mode:         types.ColorMode(""),
			wantTerminal: false,
		},
	}

	// No t.Parallel(): the cases mutate the process-global color.NoColor.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore the global fatih/color switch toggled by colorEnabled.
			orig := color.NoColor
			t.Cleanup(func() { color.NoColor = orig })

			got := colorEnabled(tt.mode, &bytes.Buffer{})
			assert.Equal(t, tt.wantTerminal, got)

			// color.NoColor is only overridden for the explicit always/never modes.
			if tt.mode == types.ColorAlways || tt.mode == types.ColorNever {
				assert.Equal(t, tt.wantNoColor, color.NoColor)
			}
		})
	}
}
