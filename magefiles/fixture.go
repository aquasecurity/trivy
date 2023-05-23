package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/magefile/mage/sh"
)

func fixtureContainerImages() error {
	const (
		testImages = "ghcr.io/aquasecurity/trivy-test-images"
		dir        = "integration/testdata/fixtures/images/"
	)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tags, err := crane.ListTags(testImages)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		fileName := tag + ".tar.gz"
		filePath := filepath.Join(dir, fileName)
		if exists(filePath) {
			continue
		}
		fmt.Printf("Downloading %s...\n", tag)
		imgName := fmt.Sprintf("%s:%s", testImages, tag)
		img, err := crane.Pull(imgName)
		if err != nil {
			return err
		}
		tarPath := strings.TrimSuffix(filePath, ".gz")
		if err = crane.Save(img, imgName, tarPath); err != nil {
			return err
		}
		if err = sh.Run("gzip", tarPath); err != nil {
			return err
		}
	}
	return nil
}

func fixtureVMImages() error {
	const (
		testVMImages    = "ghcr.io/aquasecurity/trivy-test-vm-images"
		titleAnnotation = "org.opencontainers.image.title"
		dir             = "integration/testdata/fixtures/vm-images/"
	)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tags, err := crane.ListTags(testVMImages)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		img, err := crane.Pull(fmt.Sprintf("%s:%s", testVMImages, tag))
		if err != nil {
			return err
		}

		manifest, err := img.Manifest()
		if err != nil {
			return err
		}

		layers, err := img.Layers()
		if err != nil {
			return err
		}

		for i, layer := range layers {
			fileName, ok := manifest.Layers[i].Annotations[titleAnnotation]
			if !ok {
				continue
			}
			filePath := filepath.Join(dir, fileName)
			if exists(filePath) {
				return nil
			}
			fmt.Printf("Downloading %s...\n", fileName)
			if err = saveLayer(layer, filePath); err != nil {
				return err
			}
		}
	}
	return nil
}

func saveLayer(layer v1.Layer, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	c, err := layer.Compressed()
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, c); err != nil {
		return err
	}
	return nil
}
