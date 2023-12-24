package layer

import (
	_image "github.com/kvesta/vesta/pkg/inspector"
)

type Manifest struct {
	Name      string              `json:"name"`
	Hash      string              `json:"hash"`
	Layers    []*Layer            `json:"layers"`
	Histories []*_image.ImageInfo `json:"histories"`
	Localpath string              `json:"localpath"`
}
