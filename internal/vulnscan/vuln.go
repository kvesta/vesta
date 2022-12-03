package vulnscan

import (
	"context"
	"fmt"
	"log"
	"strings"
	"vesta/config"

	"vesta/pkg/layer"
	"vesta/pkg/packages"
	"vesta/pkg/vulnlib"

	version "github.com/hashicorp/go-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
)

func (ps *Scanner) Scan(ctx context.Context, m *layer.Manifest, p *packages.Packages) error {
	log.Printf(config.Green("Begin to scan the layer"))

	err := ps.VulnDB.Init()

	if err != nil {
		log.Printf("failed to fetch database")
		return err
	}

	defer ps.VulnDB.DB.Close()

	err = ps.checkPackageVersion(ctx, p.Packs, p.OsRelease.OID)
	if err != nil {
		log.Printf("failed to check package's version")
	}

	err = ps.checkPythonModule(ctx, p.PythonPacks)
	if err != nil {
		log.Printf("failed to check python module")
	}

	err = ps.checkNpmModule(ctx, p.NodePacks)
	if err != nil {
		log.Printf("failed to check node module")
	}

	return err
}

func getInfo(row *vulnlib.DBRow, version string) *vulnComponent {
	vuln := &vulnComponent{}

	vuln.Level = row.Level
	vuln.CVEID = row.CVEID
	vuln.Desc = row.Description
	vuln.PublishDate = row.PublishDate
	vuln.Score = row.Score
	vuln.VulnerableVersion = row.MaxVersion
	vuln.CorrectVersion = version

	return vuln
}

func compareVersion(rows []*vulnlib.DBRow, cv, cp string) ([]*vulnComponent, bool) {

	var isVulnerable = false
	vulns := []*vulnComponent{}

	for _, row := range rows {

		// Skip same name which from different component
		if cp != "*" {
			if cp != row.Component {
				continue
			}
		}

		currentVersion, err := version.NewVersion(cv)
		if err != nil {
			continue
		}

		if row.MaxVersion == "*" {
			continue
		}

		if strings.Contains(row.MaxVersion, "=") {
			vulnMaxVersion, err := version.NewVersion(row.MaxVersion[1:])
			if err != nil {
				continue
			}
			if strings.Contains(row.MinVersion, "=") {
				vulnMinVersion, err := version.NewVersion(row.MinVersion[1:])
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) <= 0 &&
					currentVersion.Compare(vulnMinVersion) >= 0 {
					vuln := getInfo(row, currentVersion.String())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion, err := version.NewVersion(row.MinVersion)
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) <= 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.String())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}
			}

		} else {
			vulnMaxVersion, err := version.NewVersion(row.MaxVersion)
			if err != nil {
				continue
			}
			if strings.Contains(row.MinVersion, "=") {
				vulnMinVersion, err := version.NewVersion(row.MinVersion[1:])
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) < 0 &&
					currentVersion.Compare(vulnMinVersion) >= 0 {
					vuln := getInfo(row, currentVersion.String())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion, err := version.NewVersion(row.MinVersion)
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) < 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.String())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}
			}
		}
	}

	return vulns, isVulnerable
}

func compareRpmVersion(rows []*vulnlib.DBRow, cv string) ([]*vulnComponent, bool) {

	var isVulnerable = false
	vulns := []*vulnComponent{}

	for _, row := range rows {
		currentVersion := rpmversion.NewVersion(cv)

		if row.MaxVersion == "*" {
			continue
		}

		if strings.Contains(row.MaxVersion, "=") {
			vulnMaxVersion := rpmversion.NewVersion(row.MaxVersion[1:])

			if strings.Contains(row.MinVersion, "=") {
				vulnMinVersion := rpmversion.NewVersion(row.MinVersion[1:])

				if currentVersion.Compare(vulnMaxVersion) <= 0 &&
					currentVersion.Compare(vulnMinVersion) >= 0 {
					vuln := getInfo(row, currentVersion.Version())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion := rpmversion.NewVersion(row.MinVersion)

				if currentVersion.Compare(vulnMaxVersion) <= 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.Version())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}
			}

		} else {
			vulnMaxVersion := rpmversion.NewVersion(row.MaxVersion)

			if strings.Contains(row.MinVersion, "=") {
				vulnMinVersion := rpmversion.NewVersion(row.MinVersion[1:])

				if currentVersion.Compare(vulnMaxVersion) < 0 &&
					currentVersion.Compare(vulnMinVersion) >= 0 {
					vuln := getInfo(row, currentVersion.String())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion := rpmversion.NewVersion(row.MinVersion)

				if currentVersion.Compare(vulnMaxVersion) < 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.String())
					vulns = append(vulns, vuln)

					isVulnerable = true
				}
			}
		}
	}

	return vulns, isVulnerable
}

func (ps *Scanner) checkPythonModule(ctx context.Context, pys []*packages.Python) error {

	pyVuln := []*vulnComponent{}

	for _, py := range pys {

		for _, m := range py.SitePackes {
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(m.Name))
			if err != nil {
				continue
			}

			if vs, vuln := compareVersion(rows, m.Version, "*"); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s - %s", py.Version, m.Name)
				}
				pyVuln = append(pyVuln, vs...)
			}

		}
	}

	ps.Vulns = append(ps.Vulns, pyVuln...)

	return nil
}

func (ps *Scanner) checkNpmModule(ctx context.Context, nodes []*packages.Node) error {

	npmVuln := []*vulnComponent{}

	for _, node := range nodes {

		for _, npm := range node.NPMS {
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(npm.Name))
			if err != nil {
				continue
			}
			if vs, vuln := compareVersion(rows, npm.Version, "node.js"); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s - %s", node.Version, npm.Name)
				}
				npmVuln = append(npmVuln, vs...)

			}
		}

	}

	ps.Vulns = append(ps.Vulns, npmVuln...)

	return nil
}

func (ps *Scanner) checkPackageVersion(ctx context.Context, packs []*packages.Package, os string) error {

	packVuln := []*vulnComponent{}

	if os == "centos" || os == "rhel" {
		for _, p := range packs {
			if p.Name == "python" && p.Version < "3.0" {
				continue
			}
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(p.Name))
			if err != nil {
				continue
			}

			if vs, vuln := compareRpmVersion(rows, p.Version); vuln {
				for _, v := range vs {
					v.Name = p.Name
				}

				packVuln = append(packVuln, vs...)
			}
		}

		ps.Vulns = append(ps.Vulns, packVuln...)

		return nil
	}

	for _, p := range packs {
		rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(p.Name))
		if err != nil {
			continue
		}

		if p.Name == "python" && p.Version < "3.0" {
			continue
		}

		if vs, vuln := compareVersion(rows, p.Version, "*"); vuln {
			for _, v := range vs {
				v.Name = p.Name
			}

			packVuln = append(packVuln, vs...)
		}
	}

	ps.Vulns = append(ps.Vulns, packVuln...)

	return nil
}
