package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	hversion "github.com/hashicorp/go-version" //nolint:gomodguard // hc-install uses hashicorp/go-version
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/trivy/internal/testutil"
)

const (
	terraformVersion       = "1.7.3"
	terraformParallelLimit = 5

	tfplanFile = "tfplan"
)

func fixtureTerraformPlanSnapshots(ctx context.Context) error {
	localstackC, addr, err := testutil.SetupLocalStack(ctx, "3.1.0")
	if err != nil {
		return err
	}
	defer localstackC.Terminate(ctx)

	envs := []struct {
		key string
		val string
	}{
		{"AWS_DEFAULT_REGION", "us-east-1"},
		{"AWS_ACCESS_KEY_ID", "test"},
		{"AWS_SECRET_ACCESS_KEY", "test"},
		{"AWS_ENDPOINT_URL", addr},
	}

	for _, env := range envs {
		if err := os.Setenv(env.key, env.val); err != nil {
			return err
		}
	}

	dirs := []string{
		"pkg/fanal/artifact/local/testdata/misconfig/terraformplan/snapshots",
		"pkg/iac/scanners/terraformplan/snapshot/testdata",
	}

	var workingDirs []string

	for _, dir := range dirs {
		entries, err := os.ReadDir(filepath.FromSlash(dir))
		if err != nil {
			return err
		}

		for _, entry := range entries {
			workingDirs = append(workingDirs, filepath.Join(dir, entry.Name()))
		}
	}

	installer := &releases.ExactVersion{
		Product: product.Terraform,
		Version: hversion.Must(hversion.NewVersion(terraformVersion)),
	}

	execPath, err := installer.Install(ctx)
	if err != nil {
		return fmt.Errorf("failed to install Terraform: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(terraformParallelLimit)

	for _, workingDir := range workingDirs {
		workingDir := workingDir
		g.Go(func() error {
			if err := os.Remove(tfplanFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}

			if err := generatePlan(ctx, execPath, workingDir); err != nil {
				return fmt.Errorf("failed to generate Terraform Plan: %w", err)
			}

			return nil
		})
	}

	return g.Wait()
}

func generatePlan(ctx context.Context, execPath, workingDir string) error {
	if err := cleanup(workingDir); err != nil {
		return err
	}
	defer cleanup(workingDir)

	tf, err := tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		return fmt.Errorf("failed to run Terraform: %w", err)
	}

	prefix := fmt.Sprintf("tfplan:%s:", filepath.Base(workingDir))
	tf.SetLogger(log.New(os.Stdout, prefix, log.LstdFlags))

	if err = tf.Init(ctx, tfexec.Upgrade(true)); err != nil {
		return fmt.Errorf("failed to run Init cmd: %w", err)
	}

	if _, err := tf.Plan(ctx, tfexec.Out(tfplanFile)); err != nil {
		return fmt.Errorf("failed to run Plan cmd: %w", err)
	}

	return nil
}

func cleanup(workingDir string) error {
	entries, err := os.ReadDir(workingDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.Name() == "terraform.tfstate" || strings.HasPrefix(entry.Name(), ".terraform") {
			path := filepath.Join(workingDir, entry.Name())
			if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}
