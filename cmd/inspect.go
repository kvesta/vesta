package cmd

import (
	"context"
	"github.com/kvesta/vesta/pkg/layer"
)

// Inspect get inspector struct
func Inspect(ctx context.Context, tempPath string) (*layer.Manifest, error) {
	image := layer.Manifest{}
	if err := image.GetLayers(ctx, tempPath); err != nil {
		return nil, err
	}

	return &image, nil
}
