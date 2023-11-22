package test

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/scanners/terraform/executor"
	"github.com/aquasecurity/trivy/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/require"
)

func Test_DeterministicResults(t *testing.T) {

	reg := rules.Register(badRule)
	defer rules.Deregister(reg)

	fs := testutil.CreateFS(t, map[string]string{
		"first.tf": `
resource "problem" "uhoh" {
	bad = true
	for_each = other.thing
}
		`,
		"second.tf": `
resource "other" "thing" {
	for_each = local.list
}
		`,
		"third.tf": `
locals {
	list = {
		a = 1,
		b = 2,
	}
}
		`,
	})

	for i := 0; i < 100; i++ {
		p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
		err := p.ParseFS(context.TODO(), ".")
		require.NoError(t, err)
		modules, _, err := p.EvaluateAll(context.TODO())
		require.NoError(t, err)
		results, _, _ := executor.New().Execute(modules)
		require.Len(t, results.GetFailed(), 2)
	}
}
