package internal

import (
	"github.com/kvesta/vesta/internal/analyzer"
	"github.com/kvesta/vesta/internal/vulnscan"
	"github.com/kvesta/vesta/pkg/layer"
	"github.com/kvesta/vesta/pkg/osrelease"
	"github.com/kvesta/vesta/pkg/packages"
)

type Vuln struct {
	Scan vulnscan.Scanner
	// get layer information
	Mani *layer.Manifest
	// get os release
	OsRelease *osrelease.OsVersion
	// list all installed packages
	Packs *packages.Packages
}

type Inpsectors struct {
	Scan  analyzer.Scanner
	Kscan analyzer.KScanner
}
