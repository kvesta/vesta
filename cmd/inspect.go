package cmd

import (
	"context"
	"vesta/pkg/layer"
)

// Inspect get inspector struct
func Inspect(ctx context.Context, imagePath, tempPath string) (*layer.Manifest, error) {
	image := layer.Manifest{}
	if err := image.GetLayers(ctx, imagePath, tempPath); err != nil {
		return nil, err
	}

	return &image, nil
}
