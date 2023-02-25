package vulnscan

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/pkg/layer"
	"github.com/kvesta/vesta/pkg/match"
	"github.com/kvesta/vesta/pkg/packages"
	"github.com/kvesta/vesta/pkg/vulnlib"

	version2 "github.com/hashicorp/go-version"
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

	err = ps.checkPythonModule(ctx, p.PythonPacks, m)
	if err != nil {
		log.Printf("failed to check python module")
	}

	err = ps.checkNpmModule(ctx, p.NodePacks)
	if err != nil {
		log.Printf("failed to check node module")
	}

	err = ps.checkGoMod(ctx, p.GOPacks)
	if err != nil {
		log.Printf("failed to check go mod")
	}

	err = ps.checkJavaPacks(ctx, p.JavaPacks)
	if err != nil {
		log.Printf("failed to check go mod")
	}

	err = ps.checkPHPPacks(ctx, p.PHPPacks)
	if err != nil {
		log.Printf("failed to check php packs")
	}

	err = ps.checkRustPacks(ctx, p.RustPacks)
	if err != nil {
		log.Printf("failed to check rust packs")
	}

	return err
}

func getInfo(row *vulnlib.DBRow, version, packType string) *vulnComponent {
	vuln := &vulnComponent{}

	vuln.Level = row.Level
	vuln.CVEID = row.CVEID
	vuln.Desc = row.Description
	vuln.PublishDate = row.PublishDate
	vuln.Score = row.Score
	vuln.CurrentVersion = version
	vuln.Type = packType

	if strings.HasPrefix(row.MaxVersion, "=") {
		vuln.VulnerableVersion = "<=" + row.MaxVersion[1:]
	} else {
		vuln.VulnerableVersion = "<" + row.MaxVersion
	}

	return vuln
}

func compareVersion(rows []*vulnlib.DBRow, cv, ty string, cp []string) ([]*vulnComponent, bool) {

	var isVulnerable = false
	vulns := []*vulnComponent{}

	for _, row := range rows {

		// Skip same name which from different component
		skip := true
		for _, c := range cp {
			if c == row.Component {
				skip = false
			}
		}

		if skip {
			continue
		}

		currentVersion, err := version2.NewVersion(cv)
		if err != nil {
			continue
		}

		if row.MaxVersion == "*" {
			continue
		}

		if strings.Contains(row.MaxVersion, "=") {
			vulnMaxVersion, err := version2.NewVersion(row.MaxVersion[1:])
			if err != nil {
				continue
			}
			if strings.Contains(row.MinVersion, "=") {
				vulnMinVersion, err := version2.NewVersion(row.MinVersion[1:])
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) <= 0 &&
					currentVersion.Compare(vulnMinVersion) >= 0 {
					vuln := getInfo(row, currentVersion.String(), ty)
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion, err := version2.NewVersion(row.MinVersion)
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) <= 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.String(), ty)
					vulns = append(vulns, vuln)

					isVulnerable = true
				}
			}

		} else {
			vulnMaxVersion, err := version2.NewVersion(row.MaxVersion)
			if err != nil {
				continue
			}
			if strings.Contains(row.MinVersion, "=") {
				vulnMinVersion, err := version2.NewVersion(row.MinVersion[1:])
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) < 0 &&
					currentVersion.Compare(vulnMinVersion) >= 0 {
					vuln := getInfo(row, currentVersion.String(), ty)
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion, err := version2.NewVersion(row.MinVersion)
				if err != nil {
					continue
				}
				if currentVersion.Compare(vulnMaxVersion) < 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.String(), ty)
					vulns = append(vulns, vuln)

					isVulnerable = true
				}
			}
		}
	}

	return vulns, isVulnerable
}

func compareRpmVersion(rows []*vulnlib.DBRow, cv, ty string, cp []string) ([]*vulnComponent, bool) {

	var isVulnerable = false
	vulns := []*vulnComponent{}

	for _, row := range rows {

		// Skip same name which from different component
		skip := true
		for _, c := range cp {
			if c == row.Component {
				skip = false
			}
		}

		if skip {
			continue
		}

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
					vuln := getInfo(row, currentVersion.Version(), ty)
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion := rpmversion.NewVersion(row.MinVersion)

				if currentVersion.Compare(vulnMaxVersion) <= 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.Version(), ty)
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
					vuln := getInfo(row, currentVersion.String(), ty)
					vulns = append(vulns, vuln)

					isVulnerable = true
				}

			} else {
				vulnMinVersion := rpmversion.NewVersion(row.MinVersion)

				if currentVersion.Compare(vulnMaxVersion) < 0 &&
					currentVersion.Compare(vulnMinVersion) > 0 {
					vuln := getInfo(row, currentVersion.String(), ty)
					vulns = append(vulns, vuln)

					isVulnerable = true
				}
			}
		}
	}

	return vulns, isVulnerable
}

func listPythonSitePack(sitePath string) []string {
	targetPaths := []string{}

	fsys := os.DirFS(sitePath)

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		}

		if filepath.Base(path) == "setup.py" || filepath.Base(path) == "__init__.py" {
			targetPaths = append(targetPaths, path)
		}
		return nil

	}); err != nil {
		return targetPaths
	}

	return targetPaths
}

func (ps *Scanner) checkPythonModule(ctx context.Context, pys []*packages.Python, m *layer.Manifest) error {

	pyVuln := []*vulnComponent{}

	for _, py := range pys {

		for _, si := range py.SitePacks {
			// Get setup.py of python package

			sites := filepath.Join(m.Localpath, py.SitePath, si.Name)
			if py.SitePath == "poetry" {
				goto checkVersion
			}
			for _, p := range listPythonSitePack(sites) {
				filename := filepath.Join(sites, p)
				if sus := match.PyMalwareScan(filename); sus.Types != 0 {
					vuln := &vulnComponent{
						Name:              fmt.Sprintf("%s - %s", py.Version, si.Name),
						Level:             "high",
						Score:             8.5,
						Type:              "Python",
						CurrentVersion:    si.Version,
						VulnerableVersion: "-",
						Desc: fmt.Sprintf("Malicious package is detected in '%s', "+
							"%s", strings.TrimPrefix(filename, m.Localpath),
							sus.OriginPack),
					}

					pyVuln = append(pyVuln, vuln)

					goto checkVersion
				}
			}

		checkVersion:
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(si.Name))
			if err != nil {
				continue
			}

			if vs, vuln := compareVersion(rows, si.Version, "Python", []string{"*", "python"}); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s - %s", py.Version, si.Name)
				}

				sortSeverity(vs)
				pyVuln = append(pyVuln, vs...)
			}

			if sus := match.PyMatch(si.Name); sus.Types != 0 {
				vuln := &vulnComponent{
					Name:              fmt.Sprintf("%s - %s", py.Version, si.Name),
					Level:             "medium",
					Score:             7.5,
					Type:              "Python",
					CurrentVersion:    si.Version,
					VulnerableVersion: "-",
				}
				switch sus.Types {
				case 1:
					vuln.Desc = fmt.Sprintf("Suspicious malicious package, "+
						"compared name: %s", sus.OriginPack)
				case 2:
					vuln.Desc = fmt.Sprintf("Detect the pypi malware,"+
						"origin package name is: %s", sus.OriginPack)
				default:
					// ignore
				}

				pyVuln = append(pyVuln, vuln)
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
			if vs, vuln := compareVersion(rows, npm.Version, "Node", []string{"node.js"}); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s - %s", node.Version, npm.Name)
				}

				sortSeverity(vs)
				npmVuln = append(npmVuln, vs...)
			}

			if sus := match.NpmMatch(npm.Name); sus.Types != 0 {
				vuln := &vulnComponent{
					Name:              fmt.Sprintf("%s - %s", node.Version, npm.Name),
					Level:             "medium",
					Score:             7.5,
					Type:              "Node",
					CurrentVersion:    npm.Version,
					VulnerableVersion: "-",
				}
				switch sus.Types {
				case 1:
					vuln.Desc = fmt.Sprintf("Suspicious malicious package, "+
						"compared name: %s", sus.OriginPack)
				case 2:
					vuln.Desc = fmt.Sprintf("Detect the node malware,"+
						"origin package name is: %s", sus.OriginPack)

				default:
					// ignore
				}

				npmVuln = append(npmVuln, vuln)
			}
		}

	}

	ps.Vulns = append(ps.Vulns, npmVuln...)

	return nil
}

func (ps *Scanner) checkGoMod(ctx context.Context, gobins []*packages.GOBIN) error {

	goVuln := []*vulnComponent{}

	for _, gobin := range gobins {

		for _, mod := range gobin.Deps {
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(mod.Name))
			if err != nil {
				continue
			}
			if vs, vuln := compareVersion(rows, mod.Version, "Go", []string{"*"}); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s (%s) - %s", gobin.Name, gobin.Path, mod.Path)
				}

				sortSeverity(vs)
				goVuln = append(goVuln, vs...)
			}
		}

	}

	ps.Vulns = append(ps.Vulns, goVuln...)

	return nil
}

func (ps *Scanner) checkJavaPacks(ctx context.Context, javas []*packages.JAVA) error {

	javaVuln := []*vulnComponent{}

	for _, java := range javas {

		for _, jar := range java.Jars {
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(jar.Name))
			if err != nil {
				continue
			}
			if vs, vuln := compareVersion(rows, jar.Version, "Java", []string{"*"}); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s (%s) - %s", java.Name, java.Path, jar.Name)
				}

				sortSeverity(vs)
				javaVuln = append(javaVuln, vs...)
			}
		}

	}

	ps.Vulns = append(ps.Vulns, javaVuln...)

	return nil
}

func (ps *Scanner) checkPHPPacks(ctx context.Context, phps []*packages.PHP) error {

	phpVuln := []*vulnComponent{}

	for _, php := range phps {

		for _, pack := range php.Packs {
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(pack.Name))
			if err != nil {
				continue
			}
			if vs, vuln := compareVersion(rows, pack.Version, "PHP", []string{"*"}); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s (%s) - %s", php.Name, php.Path, pack.Name)
				}

				sortSeverity(vs)
				phpVuln = append(phpVuln, vs...)
			}
		}

	}

	ps.Vulns = append(ps.Vulns, phpVuln...)

	return nil
}

func (ps *Scanner) checkRustPacks(ctx context.Context, rusts []*packages.Rust) error {

	rustVuln := []*vulnComponent{}

	for _, cargo := range rusts {

		for _, pack := range cargo.Deps {
			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(pack.Name))
			if err != nil {
				continue
			}
			if vs, vuln := compareVersion(rows, pack.Version, "Rust", []string{"*", "rust"}); vuln {
				for _, v := range vs {
					v.Name = fmt.Sprintf("%s (%s) - %s", cargo.Name, cargo.Path, pack.Name)
				}

				sortSeverity(vs)
				rustVuln = append(rustVuln, vs...)
			}
		}

	}

	ps.Vulns = append(ps.Vulns, rustVuln...)

	return nil
}

func (ps *Scanner) checkPackageVersion(ctx context.Context, packs []*packages.Package, os string) error {

	packVuln := []*vulnComponent{}
	os = strings.ToLower(os)

	if os == "centos" || os == "rhel" {
		for _, p := range packs {

			rows, err := ps.VulnDB.QueryVulnByName(strings.ToLower(p.Name))
			if err != nil {
				continue
			}

			if vs, vuln := compareRpmVersion(rows, p.Version, "System", []string{"*"}); vuln {
				for _, v := range vs {
					v.Name = p.Name
				}

				sortSeverity(vs)
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

		if vs, vuln := compareVersion(rows, p.Version, "System", []string{"*"}); vuln {
			for _, v := range vs {
				v.Name = p.Name
			}

			sortSeverity(vs)
			packVuln = append(packVuln, vs...)
		}
	}

	ps.Vulns = append(ps.Vulns, packVuln...)

	return nil
}
