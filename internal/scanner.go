package internal

import (
	"vesta/internal/analyzer"
	"vesta/internal/vulnscan"
	"vesta/pkg/layer"
	"vesta/pkg/osrelease"
	"vesta/pkg/packages"
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
