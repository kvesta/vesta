package layer

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kvesta/vesta/pkg"
)

type Layer struct {
	Hash       string `json:"hash"`
	Annotation string `json:"path"`
}

func (l *Layer) Integration(dir, layerHash string) error {
	layerFile := filepath.Join(dir, layerHash+".tar")

	layer, err := os.Open(layerFile)
	if err != nil {
		return err
	}

	defer func() {
		layer.Close()
		os.Remove(layerFile)
	}()

	layerReader := tar.NewReader(layer)
	err = pkg.Walk(layerReader, dir)
	if err != nil {
		return fmt.Errorf("extract err: %v", err)
	}

	return nil
}
