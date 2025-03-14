package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/magefile/mage/sh"

	"github.com/aquasecurity/trivy/internal/testutil"
)

const dir = "integration/testdata/fixtures/images/"

var auth = crane.WithAuthFromKeychain(authn.NewMultiKeychain(authn.DefaultKeychain, github.Keychain))

func fixtureContainerImages() error {
	var testImages = testutil.ImageName("", "", "")

	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tags, err := crane.ListTags(testImages, auth)
	if err != nil {
		return err
	}
	// Save all tags for trivy-test-images
	for _, tag := range tags {
		if err := saveImage("", tag); err != nil {
			return err
		}
	}

	// Save trivy-test-images/containerd image
	if err := saveImage("containerd", "latest"); err != nil {
		return err
	}
	return nil
}

func saveImage(subpath, tag string) error {
	fileName := tag + ".tar.gz"
	imgName := testutil.ImageName("", tag, "")
	if subpath != "" {
		fileName = subpath + ".tar.gz"
		imgName = testutil.ImageName(subpath, "", "")
	}
	filePath := filepath.Join(dir, fileName)
	if exists(filePath) {
		return nil
	}
	fmt.Printf("Downloading %s...\n", imgName)

	img, err := crane.Pull(imgName, auth)
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
	return nil
}

func fixtureVMImages() error {
	var testVMImages = testutil.VMImageName("", "", "")
	const (
		titleAnnotation = "org.opencontainers.image.title"
		dir             = "integration/testdata/fixtures/vm-images/"
	)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tags, err := crane.ListTags(testVMImages, auth)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		img, err := crane.Pull(fmt.Sprintf("%s:%s", testVMImages, tag), auth)
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
