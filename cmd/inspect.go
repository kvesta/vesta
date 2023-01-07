package cmd

import (
	"archive/tar"
	"context"
	"github.com/kvesta/vesta/pkg/layer"
)

// Inspect get inspector struct
func Inspect(ctx context.Context, tempPath string, tarReader *tar.Reader) (*layer.Manifest, error) {
	image := layer.Manifest{}
	if err := image.GetLayers(ctx, tarReader, tempPath); err != nil {
		return nil, err
	}

	image.Localpath = tempPath

	return &image, nil
}
