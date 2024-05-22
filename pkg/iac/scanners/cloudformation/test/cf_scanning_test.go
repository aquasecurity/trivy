package test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func Test_basic_cloudformation_scanning(t *testing.T) {
	cfScanner := cloudformation.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))

	results, err := cfScanner.ScanFS(context.TODO(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	assert.NotEmpty(t, results.GetFailed())
}

func Test_cloudformation_scanning_has_expected_errors(t *testing.T) {
	cfScanner := cloudformation.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))

	results, err := cfScanner.ScanFS(context.TODO(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	assert.NotEmpty(t, results.GetFailed())
}

func Test_cloudformation_scanning_with_debug(t *testing.T) {

	debugWriter := bytes.NewBufferString("")

	scannerOptions := []options.ScannerOption{
		options.ScannerWithDebug(debugWriter),
	}
	cfScanner := cloudformation.New(scannerOptions...)

	_, err := cfScanner.ScanFS(context.TODO(), os.DirFS("./examples/bucket"), ".")
	require.NoError(t, err)

	// check debug is as expected
	assert.NotEmpty(t, debugWriter.String())
}
