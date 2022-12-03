package packages

import (
	"vesta/pkg/layer"
	"vesta/pkg/osrelease"
)

type Packages struct {
	Mani      layer.Manifest      `json:"manifest"`
	OsRelease osrelease.OsVersion `json:"os_release"`

	// List all installed packages
	Packs       []*Package `json:"packs"`
	PythonPacks []*Python  `json:"python_pack"`
	NodePacks   []*Node    `json:"node_packs"`
}

type Package struct {
	PID          string `json:"pid"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}
