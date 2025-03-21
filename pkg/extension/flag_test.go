package extension_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/flag"
)

type testOptionKey struct{}

var foo = flag.Flag[string]{
	Name:       "foo",
	ConfigName: "foo",
	Usage:      "foo",
	Default:    "default-value",
}

// testFlagGroup is a flag group for testing
type testFlagGroup struct {
	Foo *flag.Flag[string]
}

type testOptions struct {
	Foo string
}

func (fg *testFlagGroup) Name() string {
	return "TestFlagGroup"
}

func (fg *testFlagGroup) Flags() []flag.Flagger {
	return []flag.Flagger{
		fg.Foo,
	}
}

func (fg *testFlagGroup) ToOptions(opts *flag.Options) error {
	if opts.CustomOptions == nil {
		opts.CustomOptions = make(map[any]any)
	}
	opts.CustomOptions[testOptionKey{}] = testOptions{
		Foo: fg.Foo.Value(),
	}
	return nil
}

// testExtension implements the FlagExtension interface for testing
type testExtension struct{}

func (e *testExtension) Name() string {
	return "TestExtension"
}

func (e *testExtension) CustomFlagGroup(command string) flag.FlagGroup {
	if command != "image" {
		return nil
	}

	return &testFlagGroup{
		Foo: foo.Clone(),
	}
}

func TestCustomFlagGroups(t *testing.T) {
	// Set up
	te := &testExtension{}
	extension.RegisterFlagExtension(te)
	t.Cleanup(func() {
		extension.DeregisterFlagExtension(te.Name())
	})

	t.Run("flag group is set", func(t *testing.T) {
		t.Cleanup(viper.Reset)
		flags := flag.Flags(extension.CustomFlagGroups("image"))
		cmd := &cobra.Command{}
		flags.AddFlags(cmd)
		flags.Bind(cmd)

		// Test with no custom value
		opts, err := flags.ToOptions(nil)
		require.NoError(t, err)

		// Verify CustomOptions has the default value
		testOpts := extractTestOptions(t, opts)
		assert.Equal(t, "default-value", testOpts.Foo)

		// Test
		viper.Set(foo.ConfigName, "custom-value")
		opts, err = flags.ToOptions(nil)
		require.NoError(t, err)

		// Verify CustomOptions has the custom value
		testOpts = extractTestOptions(t, opts)
		assert.Equal(t, "custom-value", testOpts.Foo)
	})

	t.Run("flag group is not set", func(t *testing.T) {
		t.Cleanup(viper.Reset)
		flags := flag.Flags(extension.CustomFlagGroups("other"))
		cmd := &cobra.Command{}
		flags.AddFlags(cmd)
		flags.Bind(cmd)

		// Test
		viper.Set(foo.ConfigName, "custom-value")
		opts, err := flags.ToOptions(nil)
		require.NoError(t, err)

		// Verify CustomOptions is not set
		require.Nil(t, opts.CustomOptions)
	})
}

func extractTestOptions(t *testing.T, opts flag.Options) testOptions {
	value, ok := opts.CustomOptions[testOptionKey{}]
	require.True(t, ok)

	testOpts, ok := value.(testOptions)
	require.True(t, ok)
	return testOpts
}
