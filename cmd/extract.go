package cmd

import (
	"archive/tar"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/kvesta/vesta/pkg"
	"github.com/kvesta/vesta/pkg/layer"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}

		return false
	}
	return true
}

// mkFolder get current path and create a temp folder
func mkFolder(foldername string) string {
	pwd, _ := os.Getwd()
	tempFolder := filepath.Join(pwd, foldername)
	if !exists(tempFolder) {
		os.MkdirAll(tempFolder, os.FileMode(0755))
	}

	return tempFolder
}

// Extract extract layers from inspector tar
func Extract(ctx context.Context, tarPath string, tarIO []io.ReadCloser) (*layer.Manifest, error) {
	var tarReader *tar.Reader

	tempPath := mkFolder(RandomString())

	if tarIO == nil {
		image, err := os.Open(tarPath)

		if err != nil {
			return nil, err
		}
		defer image.Close()

		tarReader = tar.NewReader(image)
	} else {
		tarReader = tar.NewReader(tarIO[0])
	}

	// command `docker export` will generate a single file system
	// just return the directory
	if ctx.Value("tarType") == "container" {
		err := pkg.Walk(tarReader, tempPath)
		if err != nil {
			log.Printf("extract tar file failed: %v", err)
		}

		// Get mount path
		for _, mio := range tarIO[1:] {
			tarReader = tar.NewReader(mio)
			err = pkg.Walk(tarReader, tempPath)
			if err != nil {
				log.Printf("decompress mount path failed, error: %v", err)
				continue
			}
		}

		img := &layer.Manifest{
			Localpath: tempPath,
			Hash:      "container",
		}

		return img, nil
	}

	// need temp folder path to get layer.tar
	img, err := Inspect(ctx, tempPath, tarReader)
	if err != nil {
		log.Printf("Getting layers failed")
		return nil, err
	}

	// integrate all layers
	for _, l := range img.Layers {
		err := l.Integration(tempPath, l.Hash)
		if err != nil {
			continue
		}
	}

	return img, nil
}
