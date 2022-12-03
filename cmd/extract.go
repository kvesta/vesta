package cmd

import (
	"archive/tar"
	"context"
	"log"
	"os"
	"path/filepath"

	"vesta/pkg"
	"vesta/pkg/layer"
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
		//log.Printf("Create temp folder")
		os.MkdirAll(tempFolder, os.FileMode(0755))
	}

	return tempFolder
}

// Extract extract layers from inspector tar
func Extract(ctx context.Context, tarPath string) (*layer.Manifest, error) {
	tempPath := mkFolder(RandomString())

	image, err := os.Open(tarPath)

	if err != nil {
		return nil, err
	}

	defer image.Close()
	tarReader := tar.NewReader(image)

	err = pkg.Decompress(tarReader, tempPath)
	if err != nil {
		log.Printf("extract tar file failed: %v", err)
	}

	//log.Printf("Tar file extracted")

	// command `docker export` will generate a single file system
	// just return the directory
	if ctx.Value("tarType") == "container" {
		img := &layer.Manifest{
			Localpath: tempPath,
			Hash:      "container",
		}

		return img, nil
	}

	// remove all file
	defer func() {
		err := os.RemoveAll(tempPath)
		if err != nil {
			log.Printf("failed to remove %s : %v", tempPath, err)
		}
	}()

	// need temp folder path to get layer.tar
	img, err := Inspect(ctx, tarPath, tempPath)
	if err != nil {
		log.Println("Getting layers failed")
		return nil, err
	}

	imgPath := mkFolder(img.Hash)

	// integrate all layers
	for _, l := range img.Layers {
		err := l.Integration(imgPath)
		if err != nil {
			//log.Printf("layer %s integrating failed, error: %v", l.Hash, err)
			continue
		}
	}
	//log.Printf("Integrating layer successful")

	return img, nil
}
