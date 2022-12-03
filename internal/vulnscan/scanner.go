package vulnscan

import (
	"vesta/pkg/packages"
	"vesta/pkg/vulnlib"
)

type Scanner struct {
	Vulnerabilities int
	Vulns           []*vulnComponent
	VulnDB          vulnlib.Client

	VulnPacks packages.Packages
}

type vulnComponent struct {
	Name           string
	CorrectVersion string

	CVEID             string
	VulnerableVersion string
	Level             string
	PublishDate       string
	Desc              string
	Score             float64
}
