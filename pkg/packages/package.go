package packages

import (
	"github.com/kvesta/vesta/pkg/layer"
	"github.com/kvesta/vesta/pkg/osrelease"
)

type Packages struct {
	Mani      layer.Manifest      `json:"manifest"`
	OsRelease osrelease.OsVersion `json:"os_release"`

	// List all installed packages
	Packs       []*Package `json:"packs"`
	PythonPacks []*Python  `json:"python_pack"`
	NodePacks   []*Node    `json:"node_packs"`
	GOPacks     []*GOBIN   `json:"go_packs"`
	JavaPacks   []*JAVA    `json:"java_packs"`
	PHPPacks    []*PHP     `json:"php_packs"`
	RustPacks   []*Rust    `json:"rust_packs"`

	Others []*Other `json:"others"`
}

type Package struct {
	PID          string `json:"pid"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type Other struct {
	Name  string  `json:"name"`
	Title string  `json:"title"`
	Score float64 `json:"score"`
	Level string  `json:"level"`
	Desc  string  `json:"description"`
}
