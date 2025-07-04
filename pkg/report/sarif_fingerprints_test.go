package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test fingerprint generation where lines are duplicated but the previous 100 characters differ.
// This should result in a different hash for each line, even if the content is the same.
func Test_generateFingerprintFromReader(t *testing.T) {
	const testData = `def SomeFunction():
	print("Hello, World!")
	print("This is a test.")
	print("Hello, World!")
	print("It's cool to see how this works.")
`

	tests := []struct {
		name       string
		line       int
		wantPrefix string
		wantErr    bool
	}{
		{
			name:       "first print statement",
			line:       2,
			wantPrefix: "a50e3d4e70d33bd8",
			wantErr:    false,
		},
		{
			name:       "second print statement",
			line:       3,
			wantPrefix: "307130b053b79a79",
			wantErr:    false,
		},
		{
			name:       "third print statement (duplicate)",
			line:       4,
			wantPrefix: "3561eccc8d202756",
			wantErr:    false,
		},
		{
			name:       "non-existent line",
			line:       10,
			wantPrefix: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateFingerprintFromReader(strings.NewReader(testData), tt.line)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			parts := strings.SplitN(got, ":", 2)
			require.Len(t, parts, 2)
			require.Equal(t, tt.wantPrefix, parts[0])
			require.NotEmpty(t, parts[1])
		})
	}
}

// Test that the suffix is different for identical lines at the same position in the rolling window.
// As the hash is based on the previous 100 characters, we need to repetition to ensure the suffix changes as the hash is the same.
func Test_generateFingerprintFromReader_identicalHashes(t *testing.T) {
	const longLine1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz 0123456789 !@#$%^&*()_+-=[]{},.<>/?|:; 1234567890 ABCDEF\n" // 100 chars
	const testData = longLine1 + longLine1

	// Both lines are identical and start at the same position in the rolling window
	fp1, err := generateFingerprintFromReader(strings.NewReader(testData), 1)
	require.NoError(t, err)
	fp2, err := generateFingerprintFromReader(strings.NewReader(testData), 2)
	require.NoError(t, err)

	parts1 := strings.SplitN(fp1, ":", 2)
	parts2 := strings.SplitN(fp2, ":", 2)
	require.Len(t, parts1, 2)
	require.Len(t, parts2, 2)

	require.Equal(t, parts1[0], parts2[0], "Hashes should be equal for identical lines at same window position")
	require.NotEqual(t, parts1[1], parts2[1], "Suffix should be different for duplicate hashes")
}
