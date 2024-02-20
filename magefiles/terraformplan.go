package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	hversion "github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	"golang.org/x/sync/errgroup"
)

const (
	terraformVersion       = "1.7.3"
	terraformParallelLimit = 5

	tfplanFile = "tfplan"
)

func fixtureTerraformPlanSnapshots(ctx context.Context) error {

	dirs := []string{
		"pkg/fanal/artifact/local/testdata/misconfig/terraformplan/snapshots",
		"pkg/iac/scanners/terraformplan/snapshot/testdata",
	}

	var workingDirs []string

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
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
	cleanup(workingDir)
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
	for _, file := range []string{".terraform", ".terraform.lock.hcl"} {
		path := filepath.Join(workingDir, file)
		if err := os.RemoveAll(path); err != nil && errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
